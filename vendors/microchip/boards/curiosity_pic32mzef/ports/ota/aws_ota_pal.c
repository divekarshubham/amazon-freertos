/*
 * FreeRTOS OTA PAL for Curiosity PIC32MZEF V1.0.4
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

/* OTA PAL implementation for Microchip PIC32MZ platform. */
#include <sys/kmem.h>

/*lint -e9045 Ignore advisories about non-hidden definitions in header files. */

#include "ota_platform_interface.h"

/* OTA_DO_NOT_USE_CUSTOM_CONFIG allows building the OTA library
 * without a custom config. If a custom config is provided, the
 * OTA_DO_NOT_USE_CUSTOM_CONFIG macro should not be defined. */
#ifndef OTA_DO_NOT_USE_CUSTOM_CONFIG
    #include "ota_config.h"
#endif

/* Include config defaults header to get default values of configs not defined
 * in ota_config.h file. */
#include "ota_config_defaults.h"

#include "core_pkcs11.h"
#include "aws_nvm.h"
#include "iot_crypto.h"
#include "core_pkcs11_config.h"
#include "aws_ota_codesigner_certificate.h"

#include "system/reset/sys_reset.h"

/* Specify the OTA signature algorithm we support on this platform. */
const char OTA_JsonFileSignatureKey[ OTA_FILE_SIG_KEY_STR_MAX_LENGTH ] = "sig-sha256-ecdsa";

#define OTA_HALF_SECOND_DELAY            pdMS_TO_TICKS( 500UL )

/* definitions shared with the resident bootloader. */
#define AWS_BOOT_IMAGE_SIGNATURE         "@AFRTOS"
#define AWS_BOOT_IMAGE_SIGNATURE_SIZE    ( 7U )

/* Microchip PAL error codes. */

#define MCHP_ERR_NONE                       0     /* No error. */
#define MCHP_ERR_INVALID_CONTEXT            -1    /* The context valiation failed. */
#define MCHP_ERR_ADDR_OUT_OF_RANGE          -2    /* The block write address was out of range. */
#define MCHP_ERR_FLASH_WRITE_FAIL           -3    /* We failed to write data to flash. */
#define MCHP_ERR_FLASH_ERASE_FAIL           -4    /* The flash erase operation failed. */
#define MCHP_ERR_NOT_PENDING_COMMIT         -5    /* Image isn't in the Pending Commit state. */

#define AWS_BOOT_FLAG_IMG_NEW               0xffU /* 11111111b A new image that hasn't yet been run. */
#define AWS_BOOT_FLAG_IMG_PENDING_COMMIT    0xfeU /* 11111110b Image is pending commit and is ready for self test. */
#define AWS_BOOT_FLAG_IMG_VALID             0xfcU /* 11111100b The image was accepted as valid by the self test code. */
#define AWS_BOOT_FLAG_IMG_INVALID           0xf8U /* 11111000b The image was NOT accepted by the self test code. */

/*
 * Image Header.
 */
typedef union
{
    uint32_t ulAlign[ 2 ]; /* Force image header to be 8 bytes. */
    struct
    {
        char cImgSignature[ AWS_BOOT_IMAGE_SIGNATURE_SIZE ]; /* Signature identifying a valid application: AWS_BOOT_IMAGE_SIGNATURE. */
        uint8_t ucImgFlags;                                  /* Flags from the AWS_BOOT_IMAGE_FLAG_IMG*, above. */
    };                                                       /*lint !e657 This non-portable structure is strictly for the Microchip platform. */
} BootImageHeader_t;


/* Boot application image descriptor.
 * Total size is 32 bytes (NVM programming does 16 bytes at a time)
 * This is the descriptor used by the bootloader
 * to maintain the application images.
 */
typedef struct
{
    BootImageHeader_t xImgHeader; /* Application image header (8 bytes). */
    uint32_t ulSequenceNum;       /* OTA sequence number. Higher is newer. */
    /* Use byte pointers for image addresses so pointer math doesn't use incorrect scalars. */
    const uint8_t * pvStartAddr;  /* Image start address. */
    const uint8_t * pvEndAddr;    /* Image end address. */
    const uint8_t * pvExecAddr;   /* Execution start address. */
    uint32_t ulHardwareID;        /* Unique Hardware ID. */
    uint32_t ulReserved;          /* Reserved. *//*lint -e754 -e830 intentionally unreferenced alignment word. */
} BootImageDescriptor_t;

/*
 * Image Trailer.
 */
typedef struct
{
    uint8_t aucSignatureType[ OTA_FILE_SIG_KEY_STR_MAX_LENGTH ]; /* Signature Type. */
    uint32_t ulSignatureSize;                                    /* Signature size. */
    uint8_t aucSignature[ kOTA_MaxSignatureSize ];               /* Signature */
} BootImageTrailer_t;

/**
 * Regarding MISRA 2012 requirements and the following values, first, the values
 * are based on definitions in an external SDK. For maintenance and portability,
 * it is undesirable to modify the external header files or duplicate their
 * contents. Second, the values in question are, by definition of the framework,
 * valid virtual addresses that are allocated for firmware image storage.
 */

/* The current running image is always in the lower flash bank. */
static const uint8_t * pcFlashLowerBankStart = ( uint8_t * ) __KSEG0_PROGRAM_MEM_BASE; /*lint !e9048 !e9078 !e923 Please see comment header block above. */

/* The new image is always programmed in the upper flash bank. */
static const uint8_t * pcProgImageBankStart = ( uint8_t * ) ( ( uint32_t ) __KSEG0_PROGRAM_MEM_BASE + ( ( uint32_t ) __KSEG0_PROGRAM_MEM_LENGTH / 2UL ) ); /*lint !e9048 !e9078 !e923 Please see comment header block above. */
static const uint32_t ulFlashImageMaxSize = ( uint32_t ) ( ( ( uint32_t ) __KSEG0_PROGRAM_MEM_LENGTH / 2UL ) - ( uint32_t ) sizeof( BootImageDescriptor_t ) );

typedef struct
{
    const OtaFileContext_t * pxCurOTAFile; /* Current OTA file to be processed. */
    uint32_t ulLowImageOffset;             /* Lowest offset/address in the application image. */
    uint32_t ulHighImageOffset;            /* Highest offset/address in the application image. */
} OTA_OperationDescriptor_t;

/* NOTE that this implementation supports only one OTA at a time since it uses a single static instance. */
static OTA_OperationDescriptor_t xCurOTAOpDesc;         /* current OTA operation in progress. */
static OTA_OperationDescriptor_t * pxCurOTADesc = NULL; /* pointer to current OTA operation. */

static OtaErr_t prvPAL_CheckFileSignature( OtaFileContext_t * const C );
static uint8_t * prvPAL_ReadAndAssumeCertificate( const uint8_t * const pucCertName,
                                                  uint32_t * const ulSignerCertSize );
static CK_RV prvGetCertificateHandle( CK_FUNCTION_LIST_PTR pxFunctionList,
                                      CK_SESSION_HANDLE xSession,
                                      const char * pcLabelName,
                                      CK_OBJECT_HANDLE_PTR pxCertHandle );
static CK_RV prvGetCertificate( const char * pcLabelName,
                                uint8_t ** ppucData,
                                uint32_t * pulDataSize );

static __inline__ bool_t prvContextValidate( OtaFileContext_t * C )
{
    return( ( pxCurOTADesc != NULL ) && ( C != NULL ) &&
            ( pxCurOTADesc->pxCurOTAFile == C ) &&
            ( C->pFile == ( uint8_t * ) pxCurOTADesc ) ); /*lint !e9034 This preserves the abstraction layer. */
}

static __inline__ void prvContextClose( OtaFileContext_t * C )
{
    if( NULL != C )
    {
        C->pFile = NULL;
    }

    xCurOTAOpDesc.pxCurOTAFile = NULL;
    pxCurOTADesc = NULL;
}

static bool_t prvContextUpdateImageHeaderAndTrailer( OtaFileContext_t * C )
{
    BootImageHeader_t xImgHeader;
    BootImageDescriptor_t * pxImgDesc;
    BootImageTrailer_t xImgTrailer;

    memcpy( xImgHeader.cImgSignature,
            AWS_BOOT_IMAGE_SIGNATURE,
            sizeof( xImgHeader.cImgSignature ) );
    xImgHeader.ucImgFlags = AWS_BOOT_FLAG_IMG_NEW;

    /**
     * Regarding MISRA 2012 requirements and this function, the implementation
     * of the PAL is such that there are two OTA flash banks and each starts with
     * a descriptor structure.
     *
     * Virtual address translation is a requirement of the platform and the
     * translation macros are in the Microchip SDK. They require bitwise address
     * manipulation.
     */

    /* Pointer to the app descriptor in the flash upper page. */
    pxImgDesc = ( BootImageDescriptor_t * ) KVA0_TO_KVA1( pcProgImageBankStart ); /*lint !e9078 !e923 !e9027 !e9029 !e9033 !e9079 Please see the comment header block above. */

    /* Write header to flash. */
    bool_t bProgResult = ( bool_t ) AWS_FlashProgramBlock( pcProgImageBankStart,
                                                           ( const uint8_t * ) &xImgHeader,
                                                           sizeof( xImgHeader ) );

    LogDebug( ( "OTA Sequence Number: %d", pxImgDesc->ulSequenceNum ) );
    LogDebug( ( "Image - Start: 0x%08x, End: 0x%08x",
                pxImgDesc->pvStartAddr, pxImgDesc->pvEndAddr ) );

    /* If header write is successful write trailer. */
    if( bProgResult )
    {
        /* Create image trailer. */
        memcpy( xImgTrailer.aucSignatureType, OTA_JsonFileSignatureKey, sizeof( OTA_JsonFileSignatureKey ) );
        xImgTrailer.ulSignatureSize = C->pSignature->size;
        memcpy( xImgTrailer.aucSignature, C->pSignature->data, C->pSignature->size );

        /* Pointer to the trailer in the flash upper page. */
        const uint8_t * pxAppImgTrailerPtr = ( const uint8_t * ) ( pcProgImageBankStart ) + sizeof( BootImageHeader_t ) + pxCurOTADesc->ulHighImageOffset;

        /* Align it to AWS_NVM_QUAD_SIZE. */
        if( ( ( uint32_t ) pxAppImgTrailerPtr % AWS_NVM_QUAD_SIZE ) != 0 )
        {
            pxAppImgTrailerPtr += AWS_NVM_QUAD_SIZE - ( ( uint32_t ) pxAppImgTrailerPtr % AWS_NVM_QUAD_SIZE );
        }

        bProgResult = AWS_FlashProgramBlock( pxAppImgTrailerPtr, ( const uint8_t * ) &xImgTrailer, sizeof( xImgTrailer ) );

        LogDebug( ( "Writing Trailer at: 0x%08x", pxAppImgTrailerPtr ) );
    }

    return bProgResult;
}

/*
 * Turns the watchdog timer off.
 */
static void prvPAL_WatchdogDisable( void )
{
    LogDebug( ( "Disable watchdog timer." ) );

    /* Turn off the WDT. */
    WDTCONbits.ON = 0;
}


/**
 * @brief Attempts to create a new receive file to write the file chunks to as
 * they come in.
 */
OtaErr_t prvPAL_CreateFileForRx( OtaFileContext_t * const C )
{
    int32_t lErr = MCHP_ERR_NONE;
    OtaErr_t xReturnCode = OTA_ERR_UNINITIALIZED;

    /* Check parameters. The filepath is unused on this platform so ignore it. */
    if( NULL == C )
    {
        LogError( ( "context pointer is null." ) );
        lErr = MCHP_ERR_INVALID_CONTEXT;
    }
    else
    {
        /* Program this new file in the upper flash bank. */
        if( AWS_FlashEraseUpdateBank() == ( bool_t ) pdFALSE )
        {
            LogError( ( "Failed to erase the flash!" ) );
            lErr = MCHP_ERR_FLASH_ERASE_FAIL;
        }
        else
        {
            pxCurOTADesc = &xCurOTAOpDesc;
            pxCurOTADesc->pxCurOTAFile = C;
            pxCurOTADesc->ulLowImageOffset = ulFlashImageMaxSize;
            pxCurOTADesc->ulHighImageOffset = 0;

            LogInfo( ( "Receive file created." ) );
            C->pFile = ( uint8_t * ) pxCurOTADesc;
        }
    }

    if( MCHP_ERR_NONE == lErr )
    {
        xReturnCode = OTA_ERR_NONE;
    }
    else
    {
        xReturnCode = ( uint32_t ) OTA_ERR_RX_FILE_CREATE_FAILED | ( ( ( uint32_t ) lErr ) & ( uint32_t ) OTA_PAL_ERR_MASK ); /*lint !e571 intentionally cast lErr to larger composite error code. */
    }

    return xReturnCode;
}

/**
 * @brief Aborts access to an existing open file. This is only valid after a job
 * starts successfully.
 */
OtaErr_t prvPAL_Abort( OtaFileContext_t * const C )
{
    /* Check for null file handle since we may call this before a file is actually opened. */
    prvContextClose( C );
    LogInfo( ( "Abort - OK" ) );

    return OTA_ERR_NONE;
}

/* Write a block of data to the specified file.
 * Returns the number of bytes written on success or negative error code.
 */
int16_t prvPAL_WriteBlock( OtaFileContext_t * const C,
                           uint32_t ulOffset,
                           uint8_t * const pcData,
                           uint32_t ulBlockSize )
{
    int16_t sReturnVal = 0;
    uint8_t ucPadBuff[ AWS_NVM_QUAD_SIZE ];
    uint8_t * pucWriteData = pcData;
    uint32_t ulWriteBlockSzie = ulBlockSize;

    if( prvContextValidate( C ) == ( bool_t ) pdFALSE )
    {
        sReturnVal = MCHP_ERR_INVALID_CONTEXT;
    }
    else if( ( ulOffset + ulBlockSize ) > ulFlashImageMaxSize )
    { /* invalid address. */
        sReturnVal = MCHP_ERR_ADDR_OUT_OF_RANGE;
    }
    else /* Update the image offsets. */
    {
        if( ulOffset < pxCurOTADesc->ulLowImageOffset )
        {
            pxCurOTADesc->ulLowImageOffset = ulOffset;
        }

        if( ( ulOffset + ulBlockSize ) > pxCurOTADesc->ulHighImageOffset )
        {
            pxCurOTADesc->ulHighImageOffset = ulOffset + ulBlockSize;
        }

        const uint8_t * pucFlashAddr = &pcProgImageBankStart[ sizeof( BootImageHeader_t ) + ulOffset ]; /* Image descriptor is not part of the image. */

        /* NVM writes are quad word write so pad if writing less than Quad Words . */
        if( ulBlockSize < AWS_NVM_QUAD_SIZE )
        {
            memset( ucPadBuff, 0xFF, AWS_NVM_QUAD_SIZE );
            memcpy( ucPadBuff, pcData, ulBlockSize );

            pucWriteData = ucPadBuff;
            ulWriteBlockSzie = AWS_NVM_QUAD_SIZE;
        }

        if( AWS_FlashProgramBlock( pucFlashAddr, pucWriteData, ulWriteBlockSzie ) == ( bool_t ) pdFALSE )
        { /* Failed to program block to flash. */
            sReturnVal = MCHP_ERR_FLASH_WRITE_FAIL;
        }
        else
        { /* Success. */
            sReturnVal = ( int16_t ) ulBlockSize;
        }
    }

    return sReturnVal;
}

/**
 * @brief Closes the specified file. This will also authenticate the file if it
 * is marked as secure.
 */
OtaErr_t prvPAL_CloseFile( OtaFileContext_t * const C )
{
    OtaErr_t eResult = OTA_ERR_NONE;

    if( prvContextValidate( C ) == ( bool_t ) pdFALSE )
    {
        eResult = OTA_ERR_FILE_CLOSE;
    }

    if( OTA_ERR_NONE == eResult )
    {
        /* Verify that a block has actually been written by checking that the high image offset
         *  is greater than the low image offset. If that is not the case, then an invalid memory location
         *  may get passed to CRYPTO_SignatureVerificationUpdate, resulting in a data bus error. */
        if( ( C->pSignature != NULL ) &&
            ( pxCurOTADesc->ulHighImageOffset > pxCurOTADesc->ulLowImageOffset ) )
        {
            LogInfo( ( "Authenticating and closing file." ) );

            /* Verify the file signature, close the file and return the signature verification result. */
            eResult = prvPAL_CheckFileSignature( C );
        }
        else
        {
            eResult = OTA_ERR_SIGNATURE_CHECK_FAILED;
        }
    }

    if( OTA_ERR_NONE == eResult )
    {
        /* Update the image header. */
        LogDebug( ( "%s signature verification passed.", OTA_JsonFileSignatureKey ) );

        if( prvContextUpdateImageHeaderAndTrailer( C ) == ( bool_t ) pdTRUE )
        {
            LogDebug( "Image header updated." );
        }
        else
        {
            LogError( ( "Failed to update the image header." ) );
            eResult = OTA_ERR_FILE_CLOSE;
        }
    }
    else
    {
        LogError( ( "Failed to pass %s signature verification: %d.",
                    OTA_JsonFileSignatureKey, eResult ) );
    }

    prvContextClose( C );
    return eResult;
}

static OtaErr_t prvPAL_CheckFileSignature( OtaFileContext_t * const C )
{
    OtaErr_t eResult;
    uint32_t ulSignerCertSize;
    void * pvSigVerifyContext;
    uint8_t * pucSignerCert = NULL;

    /* Verify an ECDSA-SHA256 signature. */
    if( CRYPTO_SignatureVerificationStart( &pvSigVerifyContext, cryptoASYMMETRIC_ALGORITHM_ECDSA,
                                           cryptoHASH_ALGORITHM_SHA256 ) == pdFALSE )
    {
        eResult = OTA_ERR_SIGNATURE_CHECK_FAILED;
    }
    else
    {
        LogDebug( ( "Started %s signature verification, file: %s",
                    OTA_JsonFileSignatureKey, ( const char * ) C->pCertFilepath ) );
        pucSignerCert = prvPAL_ReadAndAssumeCertificate( ( const uint8_t * const ) C->pCertFilepath, &ulSignerCertSize );

        if( pucSignerCert == NULL )
        {
            eResult = OTA_ERR_BAD_SIGNER_CERT;
        }
        else
        {
            const uint8_t * pucFlashAddr = &pcProgImageBankStart[ sizeof( BootImageHeader_t ) + pxCurOTADesc->ulLowImageOffset ]; /* Image descriptor is not part of the image. */
            pucFlashAddr = ( const uint8_t * ) KVA0_TO_KVA1( pucFlashAddr );                                                      /*lint !e9078 !e923 !e9027 !e9029 !e9033 !e9079 Please see the comment header block above. */
            CRYPTO_SignatureVerificationUpdate( pvSigVerifyContext, pucFlashAddr,
                                                pxCurOTADesc->ulHighImageOffset - pxCurOTADesc->ulLowImageOffset );

            if( CRYPTO_SignatureVerificationFinal( pvSigVerifyContext, ( char * ) pucSignerCert, ulSignerCertSize,
                                                   C->pSignature->data, C->pSignature->size ) == pdFALSE )
            {
                eResult = OTA_ERR_SIGNATURE_CHECK_FAILED;

                /* Erase the image as signature verification failed.*/
                if( AWS_FlashEraseUpdateBank() == ( bool_t ) pdFALSE )
                {
                    LogError( ( "Failed to erase the flash !" ) );
                }
            }
            else
            {
                eResult = OTA_ERR_NONE;
            }
        }
    }

    /* Free the signer certificate that we now own after prvPAL_ReadAndAssumeCertificate(). */
    if( pucSignerCert != NULL )
    {
        vPortFree( pucSignerCert );
    }

    return eResult;
}


static CK_RV prvGetCertificateHandle( CK_FUNCTION_LIST_PTR pxFunctionList,
                                      CK_SESSION_HANDLE xSession,
                                      const char * pcLabelName,
                                      CK_OBJECT_HANDLE_PTR pxCertHandle )
{
    CK_ATTRIBUTE xTemplate;
    CK_RV xResult = CKR_OK;
    CK_ULONG ulCount = 0;
    CK_BBOOL xFindInit = CK_FALSE;

    /* Get the certificate handle. */
    if( 0 == xResult )
    {
        xTemplate.type = CKA_LABEL;
        xTemplate.ulValueLen = strlen( pcLabelName ) + 1;
        xTemplate.pValue = ( char * ) pcLabelName;
        xResult = pxFunctionList->C_FindObjectsInit( xSession, &xTemplate, 1 );
    }

    if( 0 == xResult )
    {
        xFindInit = CK_TRUE;
        xResult = pxFunctionList->C_FindObjects( xSession,
                                                 ( CK_OBJECT_HANDLE_PTR ) pxCertHandle,
                                                 1,
                                                 &ulCount );
    }

    if( CK_TRUE == xFindInit )
    {
        xResult = pxFunctionList->C_FindObjectsFinal( xSession );
    }

    return xResult;
}

/* Note that this function mallocs a buffer for the certificate to reside in,
 * and it is the responsibility of the caller to free the buffer. */
static CK_RV prvGetCertificate( const char * pcLabelName,
                                uint8_t ** ppucData,
                                uint32_t * pulDataSize )
{
    /* Find the certificate */
    CK_OBJECT_HANDLE xHandle;
    CK_RV xResult;
    CK_FUNCTION_LIST_PTR xFunctionList;
    CK_SLOT_ID xSlotId;
    CK_ULONG xCount = 1;
    CK_SESSION_HANDLE xSession;
    CK_ATTRIBUTE xTemplate = { 0 };
    uint8_t * pucCert = NULL;
    CK_BBOOL xSessionOpen = CK_FALSE;

    xResult = C_GetFunctionList( &xFunctionList );

    if( CKR_OK == xResult )
    {
        xResult = xFunctionList->C_Initialize( NULL );
    }

    if( ( CKR_OK == xResult ) || ( CKR_CRYPTOKI_ALREADY_INITIALIZED == xResult ) )
    {
        xResult = xFunctionList->C_GetSlotList( CK_TRUE, &xSlotId, &xCount );
    }

    if( CKR_OK == xResult )
    {
        xResult = xFunctionList->C_OpenSession( xSlotId, CKF_SERIAL_SESSION, NULL, NULL, &xSession );
    }

    if( CKR_OK == xResult )
    {
        xSessionOpen = CK_TRUE;
        xResult = prvGetCertificateHandle( xFunctionList, xSession, pcLabelName, &xHandle );
    }

    if( ( xHandle != 0 ) && ( xResult == CKR_OK ) ) /* 0 is an invalid handle */
    {
        /* Get the length of the certificate */
        xTemplate.type = CKA_VALUE;
        xTemplate.pValue = NULL;
        xResult = xFunctionList->C_GetAttributeValue( xSession, xHandle, &xTemplate, xCount );

        if( xResult == CKR_OK )
        {
            pucCert = pvPortMalloc( xTemplate.ulValueLen );
        }

        if( ( xResult == CKR_OK ) && ( pucCert == NULL ) )
        {
            xResult = CKR_HOST_MEMORY;
        }

        if( xResult == CKR_OK )
        {
            xTemplate.pValue = pucCert;
            xResult = xFunctionList->C_GetAttributeValue( xSession, xHandle, &xTemplate, xCount );

            if( xResult == CKR_OK )
            {
                *ppucData = pucCert;
                *pulDataSize = xTemplate.ulValueLen;
            }
            else
            {
                vPortFree( pucCert );
            }
        }
    }
    else /* Certificate was not found. */
    {
        *ppucData = NULL;
        *pulDataSize = 0;
    }

    if( xSessionOpen == CK_TRUE )
    {
        ( void ) xFunctionList->C_CloseSession( xSession );
    }

    return xResult;
}

/* Read the specified signer certificate from the filesystem into a local buffer. The
 * allocated memory becomes the property of the caller who is responsible for freeing it.
 */
static uint8_t * prvPAL_ReadAndAssumeCertificate( const uint8_t * const pucCertName,
                                                  uint32_t * const ulSignerCertSize )
{
    uint8_t * pucCertData;
    uint32_t ulCertSize;
    uint8_t * pucSignerCert = NULL;
    CK_RV xResult;

    xResult = prvGetCertificate( ( const char * ) pucCertName, &pucSignerCert, ulSignerCertSize );

    if( ( xResult == CKR_OK ) && ( pucSignerCert != NULL ) )
    {
        LogDebug( ( "Using cert with label: %s OK", ( const char * ) pucCertName ) );
    }
    else
    {
        LogWarn( ( "No such certificate file: %s. Using aws_ota_codesigner_certificate.h.",
                   ( const char * ) pucCertName ) );

        /* Allocate memory for the signer certificate plus a terminating zero so we can copy it and return to the caller. */
        ulCertSize = sizeof( signingcredentialSIGNING_CERTIFICATE_PEM );
        pucSignerCert = pvPortMalloc( ulCertSize + 1 );                       /*lint !e9029 !e9079 !e838 malloc proto requires void*. */
        pucCertData = ( uint8_t * ) signingcredentialSIGNING_CERTIFICATE_PEM; /*lint !e9005 we don't modify the cert but it could be set by PKCS11 so it's not const. */

        if( pucSignerCert != NULL )
        {
            memcpy( pucSignerCert, pucCertData, ulCertSize );
            /* The crypto code requires the terminating zero to be part of the length so add 1 to the size. */
            pucSignerCert[ ulCertSize ] = 0U;
            *ulSignerCertSize = ulCertSize + 1U;
        }
        else
        {
            LogError( ( "No memory for certificate of size %d!", ulCertSize ) );
        }
    }

    return pucSignerCert;
}


/* Reset the device. */

OtaErr_t prvPAL_ResetDevice( OtaFileContext_t * const C )
{
    ( void ) C;

    LogInfo( ( "Resetting the device." ) );

    /* Short delay for debug log output before reset. */
    vTaskDelay( OTA_HALF_SECOND_DELAY );
    SYS_RESET_SoftwareReset();

    /* We shouldn't actually get here if the board supports the auto reset.
     * But, it doesn't hurt anything if we do although someone will need to
     * reset the device for the new image to boot. */
    return OTA_ERR_NONE;
}


/* Activate the new MCU image by resetting the device. */

OtaErr_t prvPAL_ActivateNewImage( OtaFileContext_t * const C )
{
    LogInfo( ( "Activating the new MCU image." ) );
    return prvPAL_ResetDevice( C );
}


/* Platform specific handling of the last transferred OTA file.
 * Commit the image if the state == OtaImageStateAccepted.
 */
OtaErr_t prvPAL_SetPlatformImageState( OtaFileContext_t * const C,
                                       OtaImageState_t eState )
{
    BootImageDescriptor_t xDescCopy;
    OtaErr_t eResult = OTA_ERR_UNINITIALIZED;

    /* Descriptor handle for the image being executed, which is always the lower bank. */
    const BootImageDescriptor_t * pxAppImgDesc;

    ( void ) C;

    pxAppImgDesc = ( const BootImageDescriptor_t * ) KVA0_TO_KVA1( pcFlashLowerBankStart ); /*lint !e923 !e9027 !e9029 !e9033 !e9079 !e9078 !e9087 Please see earlier lint comment header. */
    xDescCopy = *pxAppImgDesc;                                                              /* Copy image descriptor from flash into RAM struct. */

    /* This should be an image launched in self test mode! */
    if( xDescCopy.xImgHeader.ucImgFlags == AWS_BOOT_FLAG_IMG_PENDING_COMMIT )
    {
        if( eState == OtaImageStateAccepted )
        {
            /* Mark the image as valid */
            xDescCopy.xImgHeader.ucImgFlags = AWS_BOOT_FLAG_IMG_VALID;

            if( AWS_NVM_QuadWordWrite( pxAppImgDesc->xImgHeader.ulAlign, xDescCopy.xImgHeader.ulAlign,
                                       sizeof( xDescCopy ) / AWS_NVM_QUAD_SIZE ) == ( bool_t ) pdTRUE )
            {
                LogInfo( ( "Accepted and committed final image." ) );

                /* Disable the watchdog timer. */
                prvPAL_WatchdogDisable();

                /* We always execute from the lower bank and self-test is good, we should erase the older
                 * version of the firmware by doing bank erase on upper bank. */
                if( AWS_FlashEraseUpdateBank() == ( bool_t ) pdFALSE )
                {
                    LogWarn( ( "Warning: Failed to erase the other image!" ) );
                }

                eResult = OTA_ERR_NONE;
            }
            else
            {
                LogError( ( "Accepted final image but commit failed (%d).",
                            MCHP_ERR_FLASH_WRITE_FAIL ) );
                eResult = ( uint32_t ) OTA_ERR_COMMIT_FAILED | ( ( ( uint32_t ) MCHP_ERR_FLASH_WRITE_FAIL ) & ( uint32_t ) OTA_PAL_ERR_MASK );
            }
        }
        else if( eState == OtaImageStateRejected )
        {
            /* Mark the image as invalid */
            xDescCopy.xImgHeader.ucImgFlags = AWS_BOOT_FLAG_IMG_INVALID;

            if( AWS_NVM_QuadWordWrite( pxAppImgDesc->xImgHeader.ulAlign, xDescCopy.xImgHeader.ulAlign,
                                       sizeof( xDescCopy ) / AWS_NVM_QUAD_SIZE ) == ( bool_t ) pdTRUE )
            {
                LogWarn( ( "Rejected image." ) );

                eResult = OTA_ERR_NONE;
            }
            else
            {
                LogError( ( "Failed updating the flags.(%d).",
                            MCHP_ERR_FLASH_WRITE_FAIL ) );
                eResult = ( uint32_t ) OTA_ERR_REJECT_FAILED | ( ( ( uint32_t ) MCHP_ERR_FLASH_WRITE_FAIL ) & ( uint32_t ) OTA_PAL_ERR_MASK );
            }
        }
        else if( eState == OtaImageStateAborted )
        {
            /* Mark the image as invalid */
            xDescCopy.xImgHeader.ucImgFlags = AWS_BOOT_FLAG_IMG_INVALID;

            if( AWS_NVM_QuadWordWrite( pxAppImgDesc->xImgHeader.ulAlign, xDescCopy.xImgHeader.ulAlign,
                                       sizeof( xDescCopy ) / AWS_NVM_QUAD_SIZE ) == ( bool_t ) pdTRUE )
            {
                LogWarn( ( "Aborted image." ) );

                eResult = OTA_ERR_NONE;
            }
            else
            {
                LogError( ( "Failed updating the flags.(%d).",
                            MCHP_ERR_FLASH_WRITE_FAIL ) );
                eResult = ( uint32_t ) OTA_ERR_ABORT_FAILED | ( ( ( uint32_t ) MCHP_ERR_FLASH_WRITE_FAIL ) & ( uint32_t ) OTA_PAL_ERR_MASK );
            }
        }
        else if( eState == OtaImageStateTesting )
        {
            eResult = OTA_ERR_NONE;
        }
        else
        {
            LogWarn( ( "Unknown state received %d.", ( int32_t ) eState ) );
            eResult = OTA_ERR_BAD_IMAGE_STATE;
        }
    }
    else
    {
        /* Not in self-test mode so get the descriptor for image in upper bank. */
        pxAppImgDesc = ( const BootImageDescriptor_t * ) KVA0_TO_KVA1( pcProgImageBankStart );
        xDescCopy = *pxAppImgDesc;

        if( eState == OtaImageStateAccepted )
        {
            /* We are not in self-test mode so can not set the image in upper bank as valid.  */
            LogWarn( ( "Not in commit pending so can not mark image valid (%d).",
                       MCHP_ERR_NOT_PENDING_COMMIT ) );
            eResult = ( uint32_t ) OTA_ERR_COMMIT_FAILED | ( ( ( uint32_t ) MCHP_ERR_NOT_PENDING_COMMIT ) & ( uint32_t ) OTA_PAL_ERR_MASK );
        }
        else if( eState == OtaImageStateRejected )
        {
            LogWarn( ( "Rejected image." ) );

            /* The OTA on program image bank (upper bank) is rejected so erase the bank.  */
            if( AWS_FlashEraseUpdateBank() == ( bool_t ) pdFALSE )
            {
                LogError( ( "Failed to erase the flash! (%d).",
                            MCHP_ERR_FLASH_ERASE_FAIL ) );
                eResult = ( uint32_t ) OTA_ERR_REJECT_FAILED | ( ( ( uint32_t ) MCHP_ERR_FLASH_ERASE_FAIL ) & ( uint32_t ) OTA_PAL_ERR_MASK );
            }
            else
            {
                eResult = OTA_ERR_NONE;
            }
        }
        else if( eState == OtaImageStateAborted )
        {
            LogWarn( ( "Aborted image." ) );

            /* The OTA on program image bank (upper bank) is aborted so erase the bank.  */
            if( AWS_FlashEraseUpdateBank() == ( bool_t ) pdFALSE )
            {
                LogError( ( "Failed to erase the flash! (%d).",
                            MCHP_ERR_FLASH_ERASE_FAIL ) );
                eResult = ( uint32_t ) OTA_ERR_ABORT_FAILED | ( ( ( uint32_t ) MCHP_ERR_FLASH_ERASE_FAIL ) & ( uint32_t ) OTA_PAL_ERR_MASK );
            }
            else
            {
                eResult = OTA_ERR_NONE;
            }
        }
        else if( eState == OtaImageStateTesting )
        {
            eResult = OTA_ERR_NONE;
        }
        else
        {
            eResult = OTA_ERR_BAD_IMAGE_STATE;
        }
    }

    return eResult;
}

/* Get the state of the currently running image.
 *
 * For the Microchip PIC32MZ, this reads the flag bits of the MCU image
 * header and determines the appropriate state based on that.
 *
 * We read this at OTA_Init time so we can tell if the MCU image is in self
 * test mode. If it is, we expect a successful connection to the OTA services
 * within a reasonable amount of time. If we don't satisfy that requirement,
 * we assume there is something wrong with the firmware and reset the device,
 * causing it to rollback to the previous code.
 */
OtaPalImageState_t prvPAL_GetPlatformImageState( OtaFileContext_t * const C )
{
    BootImageDescriptor_t xDescCopy;
    OtaPalImageState_t eImageState = OtaPalImageStateInvalid;
    const BootImageDescriptor_t * pxAppImgDesc;

    ( void ) C;

    pxAppImgDesc = ( const BootImageDescriptor_t * ) KVA0_TO_KVA1( pcFlashLowerBankStart ); /*lint !e923 !e9027 !e9029 !e9033 !e9079 !e9078 !e9087 Please see earlier lint comment header. */
    xDescCopy = *pxAppImgDesc;

    /**
     *  Check if valid magic code is present for the application image in lower bank.
     */
    if( memcmp( pxAppImgDesc->xImgHeader.cImgSignature,
                AWS_BOOT_IMAGE_SIGNATURE,
                AWS_BOOT_IMAGE_SIGNATURE_SIZE ) == 0 )
    {
        if( xDescCopy.xImgHeader.ucImgFlags == AWS_BOOT_FLAG_IMG_PENDING_COMMIT )
        {
            /* Pending Commit means we're in the Self Test phase. */
            eImageState = OtaPalImageStatePendingCommit;
        }
        else
        {
            /* The commit pending flag for application in lower bank is not set so we are not in self-test phase
             * so use the header flags from program bank(upper bank). */
            pxAppImgDesc = ( const BootImageDescriptor_t * ) KVA0_TO_KVA1( pcProgImageBankStart );
            xDescCopy = *pxAppImgDesc;

            /**
             *  Check if valid magic code is present for the application image in upper bank.
             */
            if( memcmp( pxAppImgDesc->xImgHeader.cImgSignature,
                        AWS_BOOT_IMAGE_SIGNATURE,
                        AWS_BOOT_IMAGE_SIGNATURE_SIZE ) == 0 )
            {
                switch( xDescCopy.xImgHeader.ucImgFlags )
                {
                    case AWS_BOOT_FLAG_IMG_PENDING_COMMIT:
                        eImageState = OtaPalImageStatePendingCommit;
                        break;

                    case AWS_BOOT_FLAG_IMG_VALID:
                    case AWS_BOOT_FLAG_IMG_NEW:
                        eImageState = OtaPalImageStateValid;
                        break;

                    default:
                        eImageState = OtaPalImageStateInvalid;
                        break;
                }
            }
        }
    }

    return eImageState;
}
