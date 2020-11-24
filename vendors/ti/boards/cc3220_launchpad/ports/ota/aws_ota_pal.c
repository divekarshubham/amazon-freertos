/*
 * FreeRTOS OTA PAL for CC3220SF-LAUNCHXL V1.0.2
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

/* OTA PAL implementation for TI CC3220SF platform. */

#include "ota.h"
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

#define kOTA_HalfSecondDelay    pdMS_TO_TICKS( 500UL )

/* TI Simplelink includes */
#include <ti/drivers/net/wifi/simplelink.h>
#include <ti/devices/cc32xx/driverlib/rom_map.h>
#include <ti/devices/cc32xx/inc/hw_types.h>
#include <ti/devices/cc32xx/driverlib/prcm.h>

/* Specify the OTA signature algorithm we support on this platform. */
const char OTA_JsonFileSignatureKey[ OTA_FILE_SIG_KEY_STR_MAX_LENGTH ] = "sig-sha1-rsa";

#define OTA_VENDOR_TOKEN             1952007250UL                   /* This is our specific file token for OTA updates. */
#define OTA_MAX_MCU_IMAGE_SIZE       ( 512UL * 1024UL )             /* Maximum allowed size of an MCU update image for this platform. */
#define OTA_MAX_PAL_WRITE_RETRIES    3U                             /* Maximum allowed block write retries (in addition to the first try). */
#define OTA_MAX_CREATE_RETRIES       1                              /* Maximum allowed retries to create the OTA receive file. */
#define OTA_SL_STOP_TIMEOUT          200U                           /* Simplelink STOP command timeout value. */
#define OTA_WDT_TIMEOUT              ( 16UL / 2UL )                 /* Use a 16 second watchdog timer. /2 for 2x factor from system clock. */
#define CC3220_WDT_START_KEY         0xAE42DB15UL                   /* TI Simplelink watchdog timer start key. */
#define CC3220_WDT_CLOCK_HZ          80000000UL                     /* The TI Simplelink watchdog clock source runs at 80MHz. */
#define OTA_FW_FILE_CHECK_FLAGS              \
    ( ( uint32_t ) SL_FS_INFO_SYS_FILE |     \
      ( uint32_t ) SL_FS_INFO_SECURE |       \
      ( uint32_t ) SL_FS_INFO_NOSIGNATURE |  \
      ( uint32_t ) SL_FS_INFO_PUBLIC_WRITE | \
      ( uint32_t ) SL_FS_INFO_PUBLIC_READ |  \
      ( uint32_t ) SL_FS_INFO_NOT_VALID )

#define OTA_FW_FILE_CHECK_GOOD           \
    ( ( uint32_t ) SL_FS_INFO_SYS_FILE | \
      ( uint32_t ) SL_FS_INFO_SECURE |   \
      ( uint32_t ) SL_FS_INFO_PUBLIC_WRITE )


typedef struct
{
    uint8_t ucActiveImg;  /*lint -e754 Intentionally unused. We use a platform independent method. */
    uint32_t ulImgStatus; /*lint -e754 Intentionally unused. We use a platform independent method. */
    uint32_t ulStartWdtKey;
    uint32_t ulStartWdtTime;
} sBootInfo_t;

/* Private functions. */
static void prvRollbackBundle( void );                 /* Call the TI CC3220SF bundle rollback API. */
static void prvRollbackRxFile( OtaFileContext_t * C ); /* Call the TI CC3220SF file rollback API. */
static int32_t prvCreateBootInfoFile( void );          /* Create the CC3220SF boot info file. */


static void prvRollbackBundle( void )
{
    int32_t lResult;
    SlFsControl_t FsControl;

    FsControl.IncludeFilters = 0U;
    lResult = sl_FsCtl( SL_FS_CTL_BUNDLE_ROLLBACK,
                        0UL,
                        ( _u8 * ) NULL,
                        ( _u8 * ) &FsControl,
                        ( _u16 ) sizeof( SlFsControl_t ),
                        ( _u8 * ) NULL,
                        0U,
                        ( _u32 * ) NULL );

    if( lResult != 0 )
    {
        LogError( ( "Bundle rollback failed (%d).", lResult ) );
    }
    else
    {
        LogInfo( ( "Bundle rollback succeeded." ) );
    }
}


static void prvRollbackRxFile( OtaFileContext_t * C )
{
    int32_t lResult;
    _u32 ulNewToken = 0UL; /* New token is not retained. */
    SlFsControl_t FsControl;

    FsControl.IncludeFilters = 0U;
    lResult = sl_FsCtl( SL_FS_CTL_ROLLBACK,
                        OTA_VENDOR_TOKEN,
                        ( _u8 * ) C->pFilePath,
                        ( _u8 * ) &FsControl,
                        ( _u16 ) sizeof( SlFsControl_t ),
                        ( _u8 * ) NULL,
                        0U,
                        ( _u32 * ) &ulNewToken );

    if( lResult != 0 )
    {
        LogError( ( "File %s rollback failed (%d).", C->pFilePath, lResult ) );
    }
    else
    {
        LogInfo( ( "File %s rolled back.", C->pFilePath ) );
    }
}


/* Abort access to an existing open file. This is only valid after a job starts successfully. */

OtaErr_t prvPAL_Abort( OtaFileContext_t * const C )
{
    /* Use this signature to abort a file transfer on the TI CC3220SF platform. */
    static _u8 pcTI_AbortSig[] = "A";

    int32_t lResult;
    /* Calling this function with a NULL file handle is not an error. */
    OtaErr_t xReturnCode = OTA_ERR_NONE;

    /* Check for null file handle since the agent may legitimately call this before a file is opened. */
    if( C->pFile != ( int32_t ) NULL )
    {
        lResult = sl_FsClose( C->pFile, ( _u8 * ) NULL, ( _u8 * ) pcTI_AbortSig, CONST_STRLEN( pcTI_AbortSig ) );
        C->pFile = ( int32_t ) NULL;

        if( lResult != 0 )
        {
            xReturnCode = ( uint32_t ) OTA_ERR_ABORT_FAILED | ( ( ( uint32_t ) lResult ) & ( uint32_t ) OTA_PAL_ERR_MASK );
        }
        else
        {
            xReturnCode = OTA_ERR_NONE;
        }

        /* We aborted the file so attempt to roll back the entire bundle. This function
         * is called by prvOTA_Close but we only rollback the bundle if there was still
         * a file handle remaining since it did not get closed from a completed file
         * transfer (therefore interpreted as an abort). */
        prvRollbackBundle();
    }

    return xReturnCode;
}


/* Attempt to create a new receive file to write the file chunks to as they come in. */

OtaErr_t prvPAL_CreateFileForRx( OtaFileContext_t * const C )
{
    _u32 ulToken = OTA_VENDOR_TOKEN; /* TI platform requires file tokens. We use a vendor token. */
    uint32_t ulFlags;                /* Flags used when opening the OTA FW image file. */
    int32_t lResult, lRetry;
    OtaErr_t xReturnCode = OTA_ERR_UNINITIALIZED;

    C->pFile = ( int32_t ) NULL;

    if( C->fileSize <= OTA_MAX_MCU_IMAGE_SIZE )
    {
        lResult = prvCreateBootInfoFile();

        /* prvCreateBootInfoFile returns the number of bytes written or negative error. 0 is not allowed. */
        if( lResult > 0 )
        {
            lRetry = 0;

            do
            {
                ulFlags = ( SL_FS_CREATE | SL_FS_OVERWRITE | SL_FS_CREATE_FAILSAFE | /*lint -e9027 -e9028 -e9029 We don't own the TI problematic macros. */
                            SL_FS_CREATE_PUBLIC_WRITE | SL_FS_WRITE_BUNDLE_FILE |
                            SL_FS_CREATE_SECURE | SL_FS_CREATE_VENDOR_TOKEN |
                            SL_FS_CREATE_MAX_SIZE( OTA_MAX_MCU_IMAGE_SIZE ) );
                /* The file remains open until the OTA agent calls prvPAL_CloseFile() after transfer or failure. */
                lResult = sl_FsOpen( ( _u8 * ) C->pFilePath, ( _u32 ) ulFlags, ( _u32 * ) &ulToken );

                if( lResult > 0 )
                {
                    LogInfo( ( "Receive file created. Token: %u", ulToken ) );
                    C->pFile = lResult;
                    xReturnCode = OTA_ERR_NONE;
                }
                else
                {
                    LogError( ( "Error (%d) trying to create receive file.", lResult ) );

                    if( lResult == SL_ERROR_FS_FILE_IS_ALREADY_OPENED )
                    {
                        /* System is in an inconsistent state and must be rebooted. */
                        if( prvPAL_ResetDevice( C ) != OTA_ERR_NONE )
                        {
                            LogError( ( "Failed to reset the device via software." ) );
                        }
                    }
                    else if( lResult == SL_ERROR_FS_FILE_IS_PENDING_COMMIT )
                    {
                        /* Attempt to roll back the receive file and try again. */
                        prvRollbackRxFile( C );
                    }
                    else
                    {
                        /* Attempt to roll back the bundle and try again. */
                        prvRollbackBundle();
                    }

                    lRetry++;
                    xReturnCode = ( uint32_t ) OTA_ERR_RX_FILE_CREATE_FAILED | ( ( ( uint32_t ) lResult ) & ( uint32_t ) OTA_PAL_ERR_MASK );
                }
            } while( ( xReturnCode != OTA_ERR_NONE ) && ( lRetry <= ( int32_t ) OTA_MAX_CREATE_RETRIES ) );
        }
        else
        {
            /* Failed to create bootinfo file. */
            xReturnCode = ( uint32_t ) OTA_ERR_BOOT_INFO_CREATE_FAILED | ( ( ( uint32_t ) lResult ) & ( uint32_t ) OTA_PAL_ERR_MASK );
        }
    }
    else
    {
        /* File is too big for the platform. */
        LogError( ( "Error (%d) trying to create receive file.", SL_ERROR_FS_FILE_MAX_SIZE_EXCEEDED ) );
        xReturnCode = ( uint32_t ) OTA_ERR_RX_FILE_TOO_LARGE | ( OTA_MAX_MCU_IMAGE_SIZE & ( uint32_t ) OTA_PAL_ERR_MASK );
    }

    return xReturnCode;
}


/* Create the required system mcubootinfo.bin file to configure the system watchdog timer. */

static int32_t prvCreateBootInfoFile( void )
{
    /* Name of the CC3220SF boot info file. */
    static const _u8 pcTI_BootInfoFilename[] = "/sys/mcubootinfo.bin"; /* Placed here for MISRA-C. */

    int32_t lFileHandle;
    uint32_t ulToken = OTA_VENDOR_TOKEN; /* Use our own explicit token for OTA files. */
    sBootInfo_t sBootInfo = { 0U };
    int32_t lReturnCode, lCloseResult;

    lFileHandle = sl_FsOpen( pcTI_BootInfoFilename,
                             SL_FS_CREATE | SL_FS_OVERWRITE | SL_FS_CREATE_MAX_SIZE( sizeof( sBootInfo ) ) |
                             SL_FS_CREATE_SECURE | SL_FS_CREATE_VENDOR_TOKEN |
                             SL_FS_CREATE_PUBLIC_WRITE | SL_FS_CREATE_NOSIGNATURE,
                             ( _u32 * ) &ulToken );     /*lint !e9087 Safe because uint32_t ulToken and _u32 are the same size on CC3220SF. */

    if( lFileHandle < 0 )
    {
        LogError( ( "Error opening bootinfo file : %d", lFileHandle ) );
        /* Propagate error to caller. */
        lReturnCode = lFileHandle;
    }
    else
    {
        memset( &sBootInfo, ( int ) 0, sizeof( sBootInfo_t ) );
        sBootInfo.ulStartWdtTime = CC3220_WDT_CLOCK_HZ * OTA_WDT_TIMEOUT;
        sBootInfo.ulStartWdtKey = CC3220_WDT_START_KEY;
        lReturnCode = sl_FsWrite( lFileHandle, 0UL, ( uint8_t * ) &sBootInfo, ( _u32 ) sizeof( sBootInfo_t ) );

        if( lReturnCode != ( int32_t ) sizeof( sBootInfo_t ) )
        {
            LogError( ( "Error writing bootinfo file : %d", lReturnCode ) );

            if( lReturnCode > 0 )
            {
                /* Force a fail result to the caller. Map to zero bytes written. */
                lReturnCode = 0;
            }

            /* Else lReturnCode is a negative error code. */
        }

        /* Close the file even after a write failure. */
        lCloseResult = sl_FsClose( lFileHandle, ( uint8_t * ) NULL, ( uint8_t * ) NULL, 0UL );

        if( lCloseResult < 0 )
        {
            LogError( ( "Error closing bootinfo file : %d", lCloseResult ) );
            /* Return the most recent error code to the caller. */
            lReturnCode = lCloseResult;
        }
    }

    return lReturnCode;
}


/* Close the specified file. This will also authenticate the file if it is marked as secure. */

OtaErr_t prvPAL_CloseFile( OtaFileContext_t * const C )
{
    int32_t lResult;
    OtaErr_t xReturnCode = OTA_ERR_UNINITIALIZED;

    /* Let SimpleLink API handle error checks so we get an error code for free. */
    LogInfo( ( "Authenticating and closing file." ) );
    lResult = ( int32_t ) sl_FsClose( ( _i32 ) ( C->pFile ), C->pCertFilepath, C->pSignature->data, ( _u32 ) ( C->pSignature->size ) );

    switch( lResult )
    {
        case 0L:
            xReturnCode = OTA_ERR_NONE;
            break;

        case SL_ERROR_FS_WRONG_SIGNATURE_SECURITY_ALERT:
        case SL_ERROR_FS_WRONG_SIGNATURE_OR_CERTIFIC_NAME_LENGTH:
        case SL_ERROR_FS_CERT_IN_THE_CHAIN_REVOKED_SECURITY_ALERT:
        case SL_ERROR_FS_INIT_CERTIFICATE_STORE:
        case SL_ERROR_FS_ROOT_CA_IS_UNKOWN:
        case SL_ERROR_FS_CERT_CHAIN_ERROR_SECURITY_ALERT:
        case SL_ERROR_FS_FILE_NOT_EXISTS:
        case SL_ERROR_FS_ILLEGAL_SIGNATURE:
        case SL_ERROR_FS_WRONG_CERTIFICATE_FILE_NAME:
        case SL_ERROR_FS_NO_CERTIFICATE_STORE:
            xReturnCode = ( uint32_t ) OTA_ERR_SIGNATURE_CHECK_FAILED | ( ( ( uint32_t ) lResult ) & ( uint32_t ) OTA_PAL_ERR_MASK ); /*lint !e571 intentionally cast lResult to larger composite error code. */
            break;

        default:                                                                                                          /*lint -e788 Keep lint quiet about the obvious unused states we're catching here. */
            xReturnCode = ( uint32_t ) OTA_ERR_FILE_CLOSE | ( ( ( uint32_t ) lResult ) & ( uint32_t ) OTA_PAL_ERR_MASK ); /*lint !e571 intentionally cast lResult to larger composite error code. */
            break;
    }

    return xReturnCode;
}


/* Reset the device. */

OtaErr_t prvPAL_ResetDevice( OtaFileContext_t * const C )
{
    ( void ) C;

    LogInfo( ( "Stopping Simplelink and resetting the device." ) );

    /* Stop Simplelink. This will activate the Bundle. Otherwise, we'll get a commit error later. */
    sl_Stop( OTA_SL_STOP_TIMEOUT ); /*lint !e534 ignore return code because we are going to reset the device below. */

    /* Short delay for debug log output before reset. */
    vTaskDelay( kOTA_HalfSecondDelay );
    MAP_PRCMHibernateCycleTrigger();

    /* We shouldn't actually get here if the board supports the auto reset.
     * But, it doesn't hurt anything if we do although someone will need to
     * reset the device for the new image to boot. */
    return OTA_ERR_RESET_NOT_SUPPORTED;
}


/* Activate the new MCU image by resetting the device. */

OtaErr_t prvPAL_ActivateNewImage( OtaFileContext_t * const C )
{
    LogInfo( ( "Activating the new MCU image." ) );
    return prvPAL_ResetDevice( C );
}


/* Platform specific handling of the last transferred OTA file/s.
 * For the TI CC3220SF, commit the file bundle if the state == OtaImageStateAccepted.
 */

OtaErr_t prvPAL_SetPlatformImageState( OtaFileContext_t * const C,
                                       OtaImageState_t eState )
{
    int32_t lResult;
    SlFsControl_t FsControl;

    FsControl.IncludeFilters = 0U;
    OtaErr_t xReturnCode = OTA_ERR_UNINITIALIZED;

    ( void ) C;

    if( eState == OtaImageStateAccepted )
    {
        PRCMPeripheralReset( ( _u32 ) PRCM_WDT );
        lResult = sl_FsCtl( SL_FS_CTL_BUNDLE_COMMIT, ( _u32 ) 0, ( _u8 * ) NULL, ( _u8 * ) &FsControl, ( _u16 ) sizeof( SlFsControl_t ), ( _u8 * ) NULL, ( _u16 ) 0, ( _u32 * ) NULL );

        if( lResult != 0 )
        {
            LogWarn( ( "Accepted final image but commit failed (%d).", lResult ) );
            xReturnCode = ( uint32_t ) OTA_ERR_COMMIT_FAILED | ( ( ( uint32_t ) lResult ) & ( uint32_t ) OTA_PAL_ERR_MASK );
        }
        else
        { /* Success. */
            LogInfo( ( "Accepted and committed final image." ) );
            xReturnCode = OTA_ERR_NONE;
        }
    }
    else if( eState == OtaImageStateRejected )
    {
        lResult = sl_FsCtl( SL_FS_CTL_BUNDLE_ROLLBACK, ( _u32 ) 0, ( _u8 * ) NULL, ( _u8 * ) &FsControl, ( _u16 ) sizeof( SlFsControl_t ), ( _u8 * ) NULL, ( _u16 ) 0, ( _u32 * ) NULL );

        if( lResult != 0 )
        {
            LogError( ( "Bundle rollback failed after reject (%d).", lResult ) );
            xReturnCode = ( uint32_t ) OTA_ERR_REJECT_FAILED | ( ( ( uint32_t ) lResult ) & ( uint32_t ) OTA_PAL_ERR_MASK );
        }
        else
        { /* Success. */
            LogWarn( ( "Image was rejected and bundle files rolled back." ) );
            xReturnCode = OTA_ERR_NONE;
        }
    }
    else if( eState == OtaImageStateAborted )
    {
        lResult = sl_FsCtl( SL_FS_CTL_BUNDLE_ROLLBACK, ( _u32 ) 0, ( _u8 * ) NULL, ( _u8 * ) &FsControl, ( _u16 ) sizeof( SlFsControl_t ), ( _u8 * ) NULL, ( _u16 ) 0, ( _u32 * ) NULL );

        if( lResult != 0 )
        {
            LogError( ( "Bundle rollback failed after abort (%d).", lResult ) );
            xReturnCode = ( uint32_t ) OTA_ERR_ABORT_FAILED | ( ( ( uint32_t ) lResult ) & ( uint32_t ) OTA_PAL_ERR_MASK );
        }
        else
        { /* Success. */
            LogWarn( ( "Agent aborted and bundle files rolled back." ) );
            xReturnCode = OTA_ERR_NONE;
        }
    }
    else if( eState == OtaImageStateTesting )
    {
        xReturnCode = OTA_ERR_NONE;
    }
    else
    {
        LogError( ( "Unknown state received %d.", ( int32_t ) eState ) );
        xReturnCode = OTA_ERR_BAD_IMAGE_STATE;
    }

    return xReturnCode;
}

/* Get the state of the currently running image.
 *
 * For the TI CC3220SF, this reads the file info of /sys/mcuflashimg.bin and
 * determines the appropriate state based on the flag bits combination.
 *
 * We read this at OTA_Init time so we can tell if the MCU image is in self
 * test mode. If it is, we expect a successful connection to the OTA services
 * within a reasonable amount of time. If we don't satisfy that requirement,
 * we assume there is something wrong with the firmware and reset the device,
 * causing it to roll back to the previous known working code. If the self tests
 * pass, the application shall call OTA_ActivateNewImage() to reset the device.
 *
 * Returns one of the following:
 *   OtaPalImageStatePendingCommit (new firmware is in the self test phase)
 *   OtaPalImageStateValid         (new firmware is valid/committed)
 *   OtaPalImageStateInvalid       (new firmware is invalid/rejected)
 */
OtaPalImageState_t prvPAL_GetPlatformImageState( OtaFileContext_t * const C )
{
    /* Specific name of the CC3220SF MCU firmware image file per CC3220SF documentation. */
    static const _u8 pcTI_FW_Filename[] = "/sys/mcuflashimg.bin";

    int32_t lResult;
    SlFsFileInfo_t xFileInfo = { 0U }; /* MISRA-C requirement. */
    OtaPalImageState_t eState = OtaPalImageStateUnknown;

    ( void ) C;

    lResult = sl_FsGetInfo( pcTI_FW_Filename, OTA_VENDOR_TOKEN, &xFileInfo );

    if( lResult == 0 )
    {
        LogDebug( ( "xFileInfo.Flags = %04x", xFileInfo.Flags ) );

        if( ( xFileInfo.Flags & ( _u16 ) SL_FS_INFO_PENDING_BUNDLE_COMMIT ) != 0U )
        {
            eState = OtaPalImageStatePendingCommit;
            LogDebug( ( "Current platform image state: OtaPalImageStatePendingCommit" ) );
        }
        else if( ( xFileInfo.Flags & OTA_FW_FILE_CHECK_FLAGS ) == OTA_FW_FILE_CHECK_GOOD )
        {
            eState = OtaPalImageStateValid;
            LogDebug( ( "Current platform image state: OtaPalImageStateValid" ) );
        }
        else /* All other combinations are considered invalid. */
        {
            eState = OtaPalImageStateInvalid;
            LogDebug( ( "Current platform image state: OtaPalImageStateInvalid" ) );
        }
    }
    else
    {
        LogError( ( "sl_FsGetInfo failed (%d) on %s", ( int32_t ) lResult, pcTI_FW_Filename ) );
        eState = OtaPalImageStateInvalid;
    }

    return eState;
}

/* Write a block of data to the specified file.
 * Returns the most recent number of bytes written upon success or a negative error code.
 */
int16_t prvPAL_WriteBlock( OtaFileContext_t * const C,
                           uint32_t ulOffset,
                           uint8_t * const pcData,
                           uint32_t ulBlockSize )
{
    int32_t lResult;
    uint32_t ulWritten = 0;
    uint32_t ulRetry;
    int16_t lReturnVal = 0;

    for( ulRetry = 0UL; ulRetry <= OTA_MAX_PAL_WRITE_RETRIES; ulRetry++ )
    {
        lResult = sl_FsWrite( C->pFile, ulOffset + ulWritten, &pcData[ ulWritten ], ulBlockSize );

        if( lResult >= 0 )
        {
            if( ulBlockSize == ( uint32_t ) lResult ) /* If we wrote all of the bytes requested, we're done. */
            {
                break;
            }
            else
            {
                ulWritten += ( uint32_t ) lResult;   /* Add to total bytes written counter. */
                ulBlockSize -= ( uint32_t ) lResult; /* Reduce block size by amount just written. */
            }
        }
        else
        {
            /* Nothing to do but retry. */
        }
    }

    if( ulRetry > OTA_MAX_PAL_WRITE_RETRIES )
    {
        LogWarn( ( "Aborted after %u retries.", OTA_MAX_PAL_WRITE_RETRIES ) );
        lReturnVal = ( int16_t ) SL_ERROR_FS_FAILED_TO_WRITE;
    }
    else
    {
        lReturnVal = ( int16_t ) lResult;
    }

    return lReturnVal;
}
