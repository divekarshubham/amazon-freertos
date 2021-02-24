/*
 * FreeRTOS OTA PAL V1.0.0
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */

/* C Runtime includes. */
#include <stdio.h>
#include <stdlib.h>

/* FreeRTOS include. */
#include "FreeRTOS.h"
#include "ota.h"
#include "ota_pal.h"
#include "ota_private.h"
#include "aws_ota_pal_settings.h"

#include "asn1utility.h"
#include "mbedtls/base64.h"
#include "nrf_mbr.h"
#include "nrf_sdm.h"
#include "nrf_nvmc.h"
#include "nrf_sdh_soc.h"
#include "nrf_crypto.h"

#include "event_groups.h"


/* Specify the OTA signature algorithm we support on this platform. */
const char OTA_JsonFileSignatureKey[ OTA_FILE_SIG_KEY_STR_MAX_LENGTH ] = "sig-sha256-ecdsa";
const char pcOTA_PAL_Magick[ otapalMAGICK_SIZE ] = "@AFRTOS";
const size_t otapalFLASH_END = ( size_t ) &__FLASH_segment_end__;
/* Tag by which the beginning of the ECDSA in the public key can be found */
const char pcOTA_PAL_ASN_1_ECDSA_TAG[] = "\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07";

const char pcOTA_PAL_CERT_BEGIN[] = "-----BEGIN CERTIFICATE-----";
const char pcOTA_PAL_CERT_END[] = "-----END CERTIFICATE-----";
static uint32_t pulSerializingArray[ otapalSERIALIZING_ARRAY_SIZE ];
size_t ulPublicKeySize = 0;

/* The static functions below (prvPAL_CheckFileSignature and prvPAL_ReadAndAssumeCertificate)
 * are optionally implemented. If these functions are implemented then please set the following macros in
 * aws_test_ota_config.h to 1:
 * otatestpalCHECK_FILE_SIGNATURE_SUPPORTED
 * otatestpalREAD_AND_ASSUME_CERTIFICATE_SUPPORTED
 */

/**
 * @brief Verify the signature of the specified file.
 *
 * This function should be implemented if signature verification is not offloaded
 * to non-volatile memory io functions.
 *
 * This function is called from prvPAL_Close().
 *
 * @param[in] C OTA file context information.
 *
 * @return Below are the valid return values for this function.
 * OTA_ERR_NONE if the signature verification passes.
 * OTA_ERR_SIGNATURE_CHECK_FAILED if the signature verification fails.
 * OTA_ERR_BAD_SIGNER_CERT if the if the signature verification certificate cannot be read.
 *
 */
static OtaErr_t prvPAL_CheckFileSignature( OtaFileContext_t * const C );

/**
 * @brief Read the specified signer certificate from the filesystem into a local buffer.
 *
 * The allocated memory returned becomes the property of the caller who is responsible for freeing it.
 *
 * This function is called from prvPAL_CheckFileSignature(). It should be implemented if signature
 * verification is not offloaded to non-volatile memory io function.
 *
 * @param[in] pucCertName The file path of the certificate file.
 * @param[out] ulSignerCertSize The size of the certificate file read.
 *
 * @return A pointer to the signer certificate in the file system. NULL if the certificate cannot be read.
 * This returned pointer is the responsibility of the caller; if the memory is allocated the caller must free it.
 */
static uint8_t * prvPAL_ReadAndAssumeCertificate( const uint8_t * const pucCertName,
                                                  uint32_t * const ulSignerCertSize );

/**
 * @brief Populates a flash memory location with an image descriptor.
 *
 * @param[in] C OTA file context information.
 *
 * @return A number of bytes written or -1 if an error happened.
 */
static ret_code_t prvPAL_WriteImageDescriptor( OtaFileContext_t * const C );

/**
 * @brief Sincronously write data to flash
 *
 * @param[in] ulOffset Position to write
 * @param[in] ulBlockSize Data size
 * @param[in] pacData Data to be written
 *
 * @return Amount of written data or -1 in the case of error
 */
static ret_code_t prvWriteFlash( uint32_t ulOffset,
                                 uint32_t ulBlockSize,
                                 uint8_t * const pacData );

static int prvNextFreeFileHandle = 1;
static EventGroupHandle_t xFlashEventGrp = NULL;

/*-----------------------------------------------------------*/

ret_code_t prvComputeSHA256Hash( void * pvMessage,
                                 size_t ulMessageSize,
                                 void * pvHashDigest,
                                 size_t * pulDigestSize );

/*-----------------------------------------------------------*/

ret_code_t prvVerifySignature( uint8_t * pusHash,
                               size_t ulHashSize,
                               uint8_t * pusSignature,
                               size_t ulSignatureSize,
                               uint8_t * pucPublicKey,
                               uint32_t ulPublicKeySize );

/*-----------------------------------------------------------*/

OtaErr_t prvErasePages( size_t xFrom,
                        size_t xTo )
{
    size_t ulErasedAddress = ( size_t ) xFrom;
    OtaErr_t xStatus = OTA_ERR_NONE;
    ret_code_t xErrCode = NRF_SUCCESS;

    while( xStatus == OTA_ERR_NONE && ulErasedAddress < ( size_t ) xTo )
    {
        size_t ulErasedPage = ( size_t ) ( ulErasedAddress / NRF_FICR->CODEPAGESIZE );
        ulErasedAddress += NRF_FICR->CODEPAGESIZE;
        xEventGroupClearBits( xFlashEventGrp, otapalFLASH_SUCCESS | otapalFLASH_FAILURE );
        xErrCode = sd_flash_page_erase( ulErasedPage );

        if( xErrCode != NRF_SUCCESS )
        {
            xStatus = OTA_ERR_RX_FILE_CREATE_FAILED;
        }
        else
        {
            /**
             * If soft device is enabled, the result of sd_flash_page_erase() is posted via event, otherwise sd_flash_page_erase()
             * is a blocking operation.
             */
            if( nrf_sdh_is_enabled() )
            {
                EventBits_t xFlashResult = xEventGroupWaitBits( xFlashEventGrp, otapalFLASH_SUCCESS | otapalFLASH_FAILURE, pdTRUE, pdFALSE, portMAX_DELAY );

                if( xFlashResult & otapalFLASH_FAILURE )
                {
                    xStatus = OTA_ERR_RX_FILE_CREATE_FAILED;
                }
            }
        }
    }

    return xStatus;
}

OtaErr_t otaPal_CreateFileForRx( OtaFileContext_t * const C )
{
    ret_code_t xErrCode;

    C->pFile = prvNextFreeFileHandle;
    OtaErr_t xStatus = OTA_ERR_NONE;

    /* Check that the second bank size is big enough to contain the new firmware */
    if( C->fileSize > otapalSECOND_BANK_SIZE )
    {
        xStatus = OTA_ERR_OUT_OF_MEMORY;
    }

    if( xStatus == OTA_ERR_NONE )
    {
        /* Create the event group for flash events */
        xFlashEventGrp = xEventGroupCreate();

        if( xFlashEventGrp == NULL )
        {
            LogError( ( "No memory for creation of event group" ) );
            xStatus = OTA_ERR_OUT_OF_MEMORY;
        }
    }

    if( xStatus == OTA_ERR_NONE )
    {
        /* Erase the required memory */
        LogInfo( ( "Erasing the flash memory" ) );
        xStatus = prvErasePages( otapalSECOND_BANK_START, otapalSECOND_BANK_END );

        if( xStatus != OTA_ERR_NONE )
        {
            LogError( ( "Erasing the flash memory failed with error_code %d", xStatus ) );
        }
    }

    return xStatus;
}
/*-----------------------------------------------------------*/

OtaErr_t otaPal_Abort( OtaFileContext_t * const C )
{
    C->pFile = ( int32_t ) NULL;

    /* Delete the event group */
    if( xFlashEventGrp != NULL )
    {
        vEventGroupDelete( xFlashEventGrp );
        xFlashEventGrp = NULL;
    }

    return OTA_ERR_NONE;
}
/*-----------------------------------------------------------*/

int16_t otaPal_WriteBlock( OtaFileContext_t * const C,
                           uint32_t ulOffset,
                           uint8_t * const pacData,
                           uint32_t ulBlockSize )
{
    /* We assume that the flash is already erased by this address (it should be, as we erase it in the
     * otaPal_CreateFileForRx, but the second write to the same position can break this invariant.
     * Anyway, the OTA procedure must not try to write to the same addresses */
    ret_code_t xErrCode = prvWriteFlash( otapalSECOND_BANK_START + otapalDESCRIPTOR_SIZE + ulOffset, ulBlockSize, pacData );

    if( xErrCode == NRF_SUCCESS )
    {
        LogDebug( ( "Write %ul bytes from the %ul address", ulBlockSize, ulOffset ) );
        return ulBlockSize;
    }
    else
    {
        LogError( ( "Write %ul bytes from the %ul address failed with error code %d",
                    ulBlockSize, ulOffset, xErrCode ) );
        return -1;
    }
}
/*-----------------------------------------------------------*/

OtaErr_t otaPal_CloseFile( OtaFileContext_t * const C )
{
    OtaErr_t xError;
    ret_code_t xStatus;

    LogInfo( ( "Erasing the flash memory was successful" ) );

    /* Write the image descriptor */
    xStatus = prvPAL_WriteImageDescriptor( C );

    if( xStatus == NRF_SUCCESS )
    {
        /* Increment the file handler */
        prvNextFreeFileHandle += 1;

        xError = prvPAL_CheckFileSignature( C );
    }
    else
    {
        xError = OTA_ERR_SIGNATURE_CHECK_FAILED;
    }

    return xError;
}
/*-----------------------------------------------------------*/


static OtaErr_t prvPAL_CheckFileSignature( OtaFileContext_t * const C )
{
    nrf_crypto_hash_sha256_digest_t xHash;
    size_t ulHashLength = sizeof( xHash );
    ret_code_t xErrCode = NRF_SUCCESS;
    uint32_t ulCertificateSize = 0;
    uint8_t * pusCertificate = prvPAL_ReadAndAssumeCertificate( NULL, &ulCertificateSize );

    if( pusCertificate == NULL )
    {
        xErrCode = NRF_ERROR_INTERNAL;
    }

    if( xErrCode == NRF_SUCCESS )
    {
        prvComputeSHA256Hash( ( uint8_t * ) otapalSECOND_BANK_START + otapalDESCRIPTOR_SIZE, C->fileSize, &xHash, &ulHashLength );
        xErrCode = prvVerifySignature( ( uint8_t * ) &xHash, ulHashLength, C->pSignature->data, C->pSignature->size, pusCertificate, ulCertificateSize );
        vPortFree( pusCertificate );
    }

    if( xErrCode != NRF_SUCCESS )
    {
        LogError( ( "Signature check failed" ) );
        return OTA_ERR_SIGNATURE_CHECK_FAILED;
    }

    LogInfo( ( "Signature check passed" ) );
    return OTA_ERR_NONE;
}
/*-----------------------------------------------------------*/

static uint8_t * prvPAL_ReadAndAssumeCertificate( const uint8_t * const pucCertName,
                                                  uint32_t * const ulSignerCertSize )
{
    uint8_t * pucPublicKey;

    *ulSignerCertSize = sizeof( signingcredentialSIGNING_CERTIFICATE_PEM );
    /* Skip the "BEGIN CERTIFICATE" */
    uint8_t * pucCertBegin = strstr( signingcredentialSIGNING_CERTIFICATE_PEM, pcOTA_PAL_CERT_BEGIN );

    if( pucCertBegin == NULL )
    {
        return NULL;
    }

    pucCertBegin += sizeof( pcOTA_PAL_CERT_BEGIN );
    /* Skip the "END CERTIFICATE" */
    uint8_t * pucCertEnd = strstr( pucCertBegin, pcOTA_PAL_CERT_END );

    if( pucCertEnd == NULL )
    {
        return NULL;
    }

    uint8_t * pucDecodedCertificate;
    size_t ulDecodedCertificateSize;
    mbedtls_base64_decode( pucDecodedCertificate, 0, &ulDecodedCertificateSize, pucCertBegin, pucCertEnd - pucCertBegin );
    pucDecodedCertificate = ( char * ) pvPortMalloc( ulDecodedCertificateSize );

    if( pucDecodedCertificate == NULL )
    {
        return NULL;
    }

    mbedtls_base64_decode( pucDecodedCertificate, ulDecodedCertificateSize, &ulDecodedCertificateSize, pucCertBegin, pucCertEnd - pucCertBegin );
    /* Find the tag of the ECDSA public signature*/
    uint8_t * pucPublicKeyStart = pucDecodedCertificate;

    while( pucPublicKeyStart < pucDecodedCertificate + ulDecodedCertificateSize )
    {
        if( memcmp( pucPublicKeyStart, pcOTA_PAL_ASN_1_ECDSA_TAG, sizeof( pcOTA_PAL_ASN_1_ECDSA_TAG ) - 1 ) == 0 )
        {
            break;
        }

        pucPublicKeyStart++;
    }

    if( pucPublicKeyStart == pucPublicKeyStart + ulDecodedCertificateSize )
    {
        vPortFree( pucDecodedCertificate );
        return NULL;
    }

    pucPublicKeyStart -= 4;
    *ulSignerCertSize = pucPublicKeyStart[ 1 ] + 2;
    vPortFree( pucDecodedCertificate );
    pucPublicKey = pvPortMalloc( *ulSignerCertSize );

    if( pucPublicKey != NULL )
    {
        memcpy( pucPublicKey, pucPublicKeyStart, *ulSignerCertSize );
    }

    return pucPublicKey;
}
/*-----------------------------------------------------------*/

OtaErr_t otaPal_ResetDevice( OtaFileContext_t * const C )
{
    ( void ) C;

    NVIC_SystemReset();
    return OTA_ERR_RESET_NOT_SUPPORTED;
}
/*-----------------------------------------------------------*/

OtaErr_t otaPal_ActivateNewImage( OtaFileContext_t * const C )
{
    ( void ) C;

    /* FIX ME. */
    otaPal_ResetDevice( C );
    return OTA_ERR_UNINITIALIZED;
}
/*-----------------------------------------------------------*/

OtaErr_t otaPal_SetPlatformImageState( OtaFileContext_t * const C,
                                       OtaImageState_t eState )
{
    OtaErr_t xStatus = OTA_ERR_NONE;

    ( void ) C;

    if( xFlashEventGrp == NULL )
    {
        /* Create the event group for flash events */
        xFlashEventGrp = xEventGroupCreate();

        if( xFlashEventGrp == NULL )
        {
            LogError( ( "No memory for creation of event group" ) );
            xStatus = OTA_ERR_OUT_OF_MEMORY;
        }
    }

    /* Read the old image */
    /* Right now we always boot from the first bank */
    /* TODO: Support boot from the second bank */
    ImageDescriptor_t * old_descriptor = ( ImageDescriptor_t * ) ( otapalFIRST_BANK_START );
    ImageDescriptor_t new_descriptor;

    /* Check if the correct image is located at the beginning of the bank */
    if( ( memcmp( old_descriptor->pMagick, pcOTA_PAL_Magick, otapalMAGICK_SIZE ) != 0 ) && ( eState == OtaImageStateAccepted ) )
    {
        xStatus = OTA_ERR_COMMIT_FAILED;
    }

    if( xStatus == OTA_ERR_NONE )
    {
        memcpy( &new_descriptor, old_descriptor, sizeof( new_descriptor ) );

        switch( eState )
        {
            case OtaImageStateAccepted:

                if( old_descriptor->usImageFlags == otapalIMAGE_FLAG_COMMIT_PENDING )
                {
                    new_descriptor.usImageFlags = otapalIMAGE_FLAG_VALID;
                }
                else
                {
                    new_descriptor.usImageFlags = otapalIMAGE_FLAG_INVALID;
                }

                break;

            case OtaImageStateRejected:
            case OtaImageStateAborted:

                if( old_descriptor->usImageFlags == otapalIMAGE_FLAG_COMMIT_PENDING )
                {
                    new_descriptor.usImageFlags = otapalIMAGE_FLAG_INVALID;
                }

                break;

            case OtaImageStateTesting:
                break;

            default:
                xStatus = OTA_ERR_BAD_IMAGE_STATE;
                break;
        }
    }

    if( xStatus == OTA_ERR_NONE )
    {
        /* We don't wont to do anything with flash if it would leave it in the same state as it were */
        if( ( new_descriptor.usImageFlags != old_descriptor->usImageFlags ) && ( eState != OtaImageStateTesting ) )
        {
            xStatus = prvErasePages( otapalFIRST_BANK_START, otapalFIRST_BANK_START + otapalDESCRIPTOR_SIZE );

            if( xStatus == OTA_ERR_NONE )
            {
                xStatus = prvWriteFlash( otapalFIRST_BANK_START, sizeof( new_descriptor ), ( uint8_t * ) &new_descriptor );
            }
        }
    }

    return xStatus;
}
/*-----------------------------------------------------------*/

OtaPalImageState_t otaPal_GetPlatformImageState( OtaFileContext_t * const C )
{
    OtaPalImageState_t xImageState = OtaPalImageStateInvalid;

    ImageDescriptor_t * descriptor = ( ImageDescriptor_t * ) ( otapalFIRST_BANK_START );

    ( void ) C;

    switch( descriptor->usImageFlags )
    {
        case otapalIMAGE_FLAG_COMMIT_PENDING:
            xImageState = OtaPalImageStatePendingCommit;
            break;

        case otapalIMAGE_FLAG_VALID:
            xImageState = OtaPalImageStateValid;
            break;

        case otapalIMAGE_FLAG_INVALID:
            xImageState = OtaPalImageStateInvalid;
            break;
    }

    return xImageState;
}
/*-----------------------------------------------------------*/

static ret_code_t prvPAL_WriteImageDescriptor( OtaFileContext_t * const C )
{
    ImageDescriptor_t xDescriptor;
    ImageDescriptor_t xOldDescriptor;
    OtaErr_t xStatus = OTA_ERR_NONE;

    memset( &xDescriptor, 0, sizeof( xDescriptor ) );

    /* Read the first bank descriptor */
    memcpy( &xOldDescriptor, ( void * ) otapalFIRST_BANK_START, sizeof( xOldDescriptor ) );

    /* Fill the new descriptor */
    if( memcmp( &xOldDescriptor.pMagick, pcOTA_PAL_Magick, otapalMAGICK_SIZE ) == 0 ) /* Check if an AFR image contained in the first bank */
    {
        xDescriptor.ulSequenceNumber = xOldDescriptor.ulSequenceNumber + 1;
    }
    else /* It seems that the first bank contains a classic Nordic image */
    {
        xDescriptor.ulSequenceNumber = 1;
    }

    memcpy( &xDescriptor.pMagick, pcOTA_PAL_Magick, otapalMAGICK_SIZE );
    xDescriptor.ulStartAddress = otapalFIRST_BANK_START + otapalDESCRIPTOR_SIZE;
    xDescriptor.ulEndAddress = xDescriptor.ulStartAddress + C->fileSize;
    xDescriptor.ulExecutionAddress = xDescriptor.ulStartAddress; /* TODO: Check if this assumption is true */
    xDescriptor.ulHardwareID = 0;                                /* TODO: Fill the Hardware ID */
    xDescriptor.usImageFlags = otapalIMAGE_FLAG_NEW;
    xDescriptor.ulSignatureSize = C->pSignature->size;

    if( C->pSignature != NULL )
    {
        if( C->pSignature->size <= kOTA_MaxSignatureSize )
        {
            memcpy( &xDescriptor.pSignature, C->pSignature->data, C->pSignature->size );
        }
    }

    prvErasePages( otapalSECOND_BANK_START, otapalSECOND_BANK_START + otapalDESCRIPTOR_SIZE );
    return prvWriteFlash( otapalSECOND_BANK_START, sizeof( xDescriptor ), ( uint8_t * ) &xDescriptor );
}

/*-----------------------------------------------------------*/

/* Write a block of data to the specified file. */
ret_code_t prvWriteFlash( uint32_t ulOffset,
                          uint32_t ulBlockSize,
                          uint8_t * const pacData )
{
    uint32_t ulByteSent, ulByteToSend;
    ret_code_t xErrCode = NRF_SUCCESS;

    ulByteSent = 0;

    while( ulByteSent < ulBlockSize )
    {
        ulByteToSend = ulBlockSize - ulByteSent;

        if( ulByteToSend > otapalSERIALIZING_ARRAY_SIZE * 4 )
        {
            ulByteToSend = otapalSERIALIZING_ARRAY_SIZE * 4;
        }

        if( ulByteToSend > NRF_FICR->CODEPAGESIZE )
        {
            ulByteToSend = NRF_FICR->CODEPAGESIZE * 4;
        }

        /* clear buffer to avoid garbage. */
        pulSerializingArray[ ( ulByteToSend + 3 ) / 4 ] = 0;
        memcpy( pulSerializingArray, pacData + ulByteSent, ulByteToSend );

        xEventGroupClearBits( xFlashEventGrp, otapalFLASH_SUCCESS | otapalFLASH_FAILURE );
        /* Softdevice can write only by 32-bit words */
        ret_code_t xErrCode = sd_flash_write( ( uint32_t * ) ( ulOffset + ulByteSent ), pulSerializingArray, ( ulByteToSend + 3 ) / 4 );

        if( xErrCode == NRF_SUCCESS )
        {
            /**
             * If soft device is enabled, the result of sd_flash_write() is posted via event, otherwise sd_flash_write()
             * is a blocking operation.
             */
            if( nrf_sdh_is_enabled() )
            {
                EventBits_t xFlashResult = xEventGroupWaitBits( xFlashEventGrp, otapalFLASH_SUCCESS | otapalFLASH_FAILURE, pdTRUE, pdFALSE, portMAX_DELAY );

                if( xFlashResult & otapalFLASH_FAILURE )
                {
                    xErrCode = NRF_ERROR_INTERNAL;
                    break;
                }
            }
        }

        ulByteSent += ulByteToSend;
    }

    return xErrCode;
}
/*-----------------------------------------------------------*/

ret_code_t prvComputeSHA256Hash( void * pvMessage,
                                 size_t ulMessageSize,
                                 void * pvHashDigest,
                                 size_t * pulDigestSize )
{
    /* We are computing the hash of memory stored on the flash so we need to first move it to ram to use CC310
     * That's why we are computing the hash by chunks */
    ret_code_t err_code;
    static nrf_crypto_hash_context_t hash_context;

    err_code = nrf_crypto_hash_init( &hash_context, &g_nrf_crypto_hash_sha256_info );
    uint8_t pulMemBuffer[ 256 ];
    size_t ulConsumed = 0;

    while( err_code == NRF_SUCCESS && ulConsumed < ulMessageSize )
    {
        size_t ulToConsume = MIN( ulMessageSize - ulConsumed, 256 );
        memcpy( pulMemBuffer, pvMessage + ulConsumed, ulToConsume );
        err_code = nrf_crypto_hash_update( &hash_context, pulMemBuffer, ulToConsume );
        ulConsumed += ulToConsume;
    }

    if( err_code == NRF_SUCCESS )
    {
        err_code = nrf_crypto_hash_finalize( &hash_context, pvHashDigest, pulDigestSize );
    }

    return err_code;
}

/*-----------------------------------------------------------*/

ret_code_t prvVerifySignature( uint8_t * pusHash,
                               size_t ulHashSize,
                               uint8_t * pusSignature,
                               size_t ulSignatureSize,
                               uint8_t * pucPublicKey,
                               uint32_t ulPublicKeySize )
{
    ret_code_t xErrCode;
    nrf_crypto_ecdsa_verify_context_t xVerifyContext;
    nrf_crypto_ecc_public_key_t xPublicKey;
    nrf_crypto_ecdsa_signature_t xSignature;
    uint8_t * pucTmpPublicKey;

    memset( &xPublicKey, 0, sizeof( xPublicKey ) );
    memset( &xSignature, 0, sizeof( xSignature ) );

    /* The public key comes in the ASN.1 DER format,  and so we need everything
     * except the DER metadata which fortunately in this case is containded in the front part of buffer */
    pucTmpPublicKey = pucPublicKey + ( ulPublicKeySize - NRF_CRYPTO_ECC_SECP256R1_RAW_PUBLIC_KEY_SIZE );
    /* Convert the extracted public key to the NRF5 representation */
    xErrCode = nrf_crypto_ecc_public_key_from_raw( &g_nrf_crypto_ecc_secp256r1_curve_info, &xPublicKey, pucTmpPublicKey, NRF_CRYPTO_ECC_SECP256R1_RAW_PUBLIC_KEY_SIZE );

    if( xErrCode == NRF_SUCCESS )
    {
        /* The signature is also ASN.1 DER encoded, but here we need to decode it properly */
        xErrCode = asn1_decodeSignature( xSignature, pusSignature, pusSignature + ulSignatureSize );
    }

    if( xErrCode == 0 )
    {
        /* Aand... Verify! */
        xErrCode = nrf_crypto_ecdsa_verify( &xVerifyContext,                             /* Context */
                                            &xPublicKey,                                 /* Public key */
                                            pusHash,                                     /* Message hash */
                                            ulHashSize,                                  /* Hash size */
                                            xSignature,                                  /* Signature */
                                            NRF_CRYPTO_ECDSA_SECP256R1_SIGNATURE_SIZE ); /* Signature size */
    }

    return xErrCode;
}

/*-----------------------------------------------------------*/

void flash_event_handler( uint32_t evt_id,
                          void * p_context )
{
    switch( evt_id )
    {
        case NRF_EVT_FLASH_OPERATION_SUCCESS:

            if( xFlashEventGrp != NULL )
            {
                xEventGroupSetBits( xFlashEventGrp, otapalFLASH_SUCCESS );
            }

            break;

        case NRF_EVT_FLASH_OPERATION_ERROR:

            if( xFlashEventGrp != NULL )
            {
                xEventGroupSetBits( xFlashEventGrp, otapalFLASH_FAILURE );
            }

            break;
    }
}

NRF_SDH_SOC_OBSERVER( flash_observer, BLE_DFU_SOC_OBSERVER_PRIO, flash_event_handler, NULL );

OtaErr_t testCheckSignature()
{
    OtaFileContext_t C;
    uint32_t ulCertSize = sizeof( signingcredentialSIGNING_CERTIFICATE_PEM );
    uint8_t * pusCertificate = prvPAL_ReadAndAssumeCertificate( signingcredentialSIGNING_CERTIFICATE_PEM, &ulCertSize );

    vPortFree( pusCertificate );
    ImageDescriptor_t * descriptor = ( ImageDescriptor_t * ) ( otapalSECOND_BANK_START );
    C.fileSize = descriptor->ulEndAddress - descriptor->ulStartAddress;
    return prvPAL_CheckFileSignature( &C );
}
