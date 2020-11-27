/*
 * FreeRTOS V202011.00
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

/**
 * @file aws_iot_ota_update_demo.c
 * @brief A simple OTA update example.
 *
 * This example initializes the OTA agent to enable OTA updates via the
 * MQTT broker. It simply connects to the MQTT broker with the users
 * credentials and spins in an indefinite loop to allow MQTT messages to be
 * forwarded to the OTA agent for possible processing. The OTA agent does all
 * of the real work; checking to see if the message topic is one destined for
 * the OTA agent. If not, it is simply ignored.
 */

/* Standard includes. */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Include common demo header. */
#include "aws_demo.h"

/* Kernel includes. */
#include "FreeRTOS.h"
#include "task.h"

/* MQTT library includes. */
#include "core_mqtt.h"
#include "mqtt_subscription_manager.h"

/* HTTP Library include. */
#include "core_http_client.h"

/* Common HTTP demo utilities. */
#include "http_demo_utils.h"

/* Retry utilities include. */
#include "backoff_algorithm.h"

/* Include PKCS11 helpers header. */
#include "pkcs11_helpers.h"

/* Transport interface implementation include header for TLS. */
#include "transport_secure_sockets.h"

/* Include header for connection configurations. */
#include "aws_clientcredential.h"

/* Include header for client credentials. */
#include "aws_clientcredential_keys.h"

/* Include header for root CA certificates. */
#include "iot_default_root_certificates.h"

/* OTA Library include. */
#include "ota.h"
#include "ota_config.h"
#include "ota_private.h"

/* OTA Library Interface include. */
#include "ota_os_freertos.h"
#include "ota_mqtt_interface.h"
#include "ota_platform_interface.h"

/* Include firmware version struct definition. */
#include "ota_appversion32.h"

/* Include platform abstraction header. */
#include "ota_pal.h"

/*------------- Demo configurations -------------------------*/

/** Note: The device client certificate and private key credentials are
 * obtained by the transport interface implementation (with Secure Sockets)
 * from the demos/include/aws_clientcredential_keys.h file.
 *
 * The following macros SHOULD be defined for this demo which uses both server
 * and client authentications for TLS session:
 *   - keyCLIENT_CERTIFICATE_PEM for client certificate.
 *   - keyCLIENT_PRIVATE_KEY_PEM for client private key.
 */

/**
 * @brief The MQTT broker endpoint used for this demo.
 */
#ifndef democonfigMQTT_BROKER_ENDPOINT
    #define democonfigMQTT_BROKER_ENDPOINT    clientcredentialMQTT_BROKER_ENDPOINT
#endif

/**
 * @brief The root CA certificate belonging to the broker.
 */
#ifndef democonfigROOT_CA_PEM
    #define democonfigROOT_CA_PEM    tlsATS1_ROOT_CERTIFICATE_PEM
#endif

#ifndef democonfigCLIENT_IDENTIFIER

/**
 * @brief The MQTT client identifier used in this example.  Each client identifier
 * must be unique so edit as required to ensure no two clients connecting to the
 * same broker use the same client identifier.
 */
    #define democonfigCLIENT_IDENTIFIER    clientcredentialIOT_THING_NAME
#endif

#ifndef democonfigMQTT_BROKER_PORT

/**
 * @brief The port to use for the demo.
 */
    #define democonfigMQTT_BROKER_PORT    clientcredentialMQTT_BROKER_PORT
#endif

/**
 * @brief Transport timeout in milliseconds for transport send and receive.
 */
#define otaexampleTRANSPORT_SEND_RECV_TIMEOUT_MS    ( 500U )

/**
 * @brief The maximum number of retries for network operation with server.
 */
#define RETRY_MAX_ATTEMPTS                          ( 5U )

/**
 * @brief The maximum back-off delay (in milliseconds) for retrying failed operation
 *  with server.
 */
#define RETRY_MAX_BACKOFF_DELAY_MS                  ( 5000U )

/**
 * @brief The base back-off delay (in milliseconds) to use for network operation retry
 * attempts.
 */
#define RETRY_BACKOFF_BASE_MS                       ( 500U )

/**
 * @brief Size of the network buffer for MQTT packets.
 */
#define otaexampleNETWORK_BUFFER_SIZE               ( 2048U )

/**
 * @brief The maximum size of the file paths used in the demo.
 */
#define otaexampleMAX_FILE_PATH_SIZE                ( 260 )

/**
 * @brief The maximum size of the stream name required for downloading update file
 * from streaming service.
 */
#define otaexampleMAX_STREAM_NAME_SIZE              ( 128 )

/**
 * @brief The delay used in the main OTA Demo task loop to periodically output the OTA
 * statistics like number of packets received, dropped, processed and queued per connection.
 */
#define otaexampleTASK_DELAY_MS                     ( 1000UL )

/**
 * @brief Keep alive time reported to the broker while establishing
 * an MQTT connection.
 *
 * @brief The maximum time interval that is permitted to elapse between the point at
 * which the MQTT client finishes transmitting one control Packet and the point it starts
 * sending the next.In the absence of control packet a PINGREQ  is sent. The broker must
 * disconnect a client that does not send a message or a PINGREQ packet in one and a
 * half times the keep alive interval. It is the responsibility of the Client to ensure
 * that the interval between Control Packets being sent does not exceed the this Keep Alive
 * value. In the absence of sending any other Control Packets, the Client MUST send a
 * PINGREQ Packet.
 */
#define otaexampleKEEP_ALIVE_TIMEOUT_SECONDS        ( 60U )

/**
 * @brief Timeout for receiving CONNACK packet in milliseconds.
 */
#define otaexampleCONNACK_RECV_TIMEOUT_MS           ( 1000U )

/**
 * @brief OTA Library task stack size in words.
 */
#define otaexampleSTACK_SIZE                        ( 1024U )

/**
 * @brief Milliseconds per second.
 */
#define MILLISECONDS_PER_SECOND                     ( 1000U )

/**
 * @brief Milliseconds per FreeRTOS tick.
 */
#define MILLISECONDS_PER_TICK                       ( MILLISECONDS_PER_SECOND / configTICK_RATE_HZ )

/**
 * @brief OTA example max host address size.
 */
#define otaexampleMAX_HOST_ADDR_SIZE                ( 256U )

/**
 * @brief HTTP server port number.
 *
 * In general, port 443 is for TLS HTTP connections.
 */
#ifndef democonfigHTTPS_PORT
    #define democonfigHTTPS_PORT    443
#endif

/**
 * @brief The host address string extracted from the pre-signed URL.
 */
static char cServerHost[ otaexampleMAX_HOST_ADDR_SIZE ];

/**
 * @brief The length of the host address found in the pre-signed URL.
 */
static size_t xServerHostLength;

/* Check that size of the user buffer is defined. */
#ifndef USER_BUFFER_LENGTH
    #define USER_BUFFER_LENGTH    ( 4096 )
#endif

/**
 * @brief A buffer used in the demo for storing HTTP request headers and
 * HTTP response headers and body.
 *
 * @note This demo shows how the same buffer can be re-used for storing the HTTP
 * response after the HTTP request is sent out. However, the user can also
 * decide to use separate buffers for storing the HTTP request and response.
 */
static uint8_t userBuffer[ USER_BUFFER_LENGTH ];

/**
 * @brief Configure application version.
 */

#define APP_VERSION_MAJOR    0
#define APP_VERSION_MINOR    9
#define APP_VERSION_BUILD    2

/**
 * @brief Update File path buffer.
 */
uint8_t updateFilePath[ otaexampleMAX_FILE_PATH_SIZE ];

/**
 * @brief Certificate File path buffer.
 */
uint8_t certFilePath[ otaexampleMAX_FILE_PATH_SIZE ];

/**
 * @brief Stream name buffer.
 */
uint8_t streamName[ otaexampleMAX_STREAM_NAME_SIZE ];

/**
 * @brief Decode memory.
 */
uint8_t decodeMem[ ( 1U << otaconfigLOG2_FILE_BLOCK_SIZE ) ];

/**
 * @brief Bitmap memory.
 */
uint8_t bitmap[ OTA_MAX_BLOCK_BITMAP_SIZE ];

/*
 * @brief Server's root CA certificate for TLS authentication with S3.
 *
 * The Baltimore Cybertrust Root CA Certificate is defined below.
 *
 * @note This certificate should be PEM-encoded.
 *
 * Must include the PEM header and footer:
 * "-----BEGIN CERTIFICATE-----\n"\
 * "...base64 data...\n"\
 * "-----END CERTIFICATE-----\n"
 *
 */
#ifndef democonfigBA_ROOT_CA_PEM
    #define democonfigBA_ROOT_CA_PEM                                     \
    "-----BEGIN CERTIFICATE-----\n"                                      \
    "MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ\n" \
    "RTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYD\n" \
    "VQQDExlCYWx0aW1vcmUgQ3liZXJUcnVzdCBSb290MB4XDTAwMDUxMjE4NDYwMFoX\n" \
    "DTI1MDUxMjIzNTkwMFowWjELMAkGA1UEBhMCSUUxEjAQBgNVBAoTCUJhbHRpbW9y\n" \
    "ZTETMBEGA1UECxMKQ3liZXJUcnVzdDEiMCAGA1UEAxMZQmFsdGltb3JlIEN5YmVy\n" \
    "VHJ1c3QgUm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKMEuyKr\n" \
    "mD1X6CZymrV51Cni4eiVgLGw41uOKymaZN+hXe2wCQVt2yguzmKiYv60iNoS6zjr\n" \
    "IZ3AQSsBUnuId9Mcj8e6uYi1agnnc+gRQKfRzMpijS3ljwumUNKoUMMo6vWrJYeK\n" \
    "mpYcqWe4PwzV9/lSEy/CG9VwcPCPwBLKBsua4dnKM3p31vjsufFoREJIE9LAwqSu\n" \
    "XmD+tqYF/LTdB1kC1FkYmGP1pWPgkAx9XbIGevOF6uvUA65ehD5f/xXtabz5OTZy\n" \
    "dc93Uk3zyZAsuT3lySNTPx8kmCFcB5kpvcY67Oduhjprl3RjM71oGDHweI12v/ye\n" \
    "jl0qhqdNkNwnGjkCAwEAAaNFMEMwHQYDVR0OBBYEFOWdWTCCR1jMrPoIVDaGezq1\n" \
    "BE3wMBIGA1UdEwEB/wQIMAYBAf8CAQMwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3\n" \
    "DQEBBQUAA4IBAQCFDF2O5G9RaEIFoN27TyclhAO992T9Ldcw46QQF+vaKSm2eT92\n" \
    "9hkTI7gQCvlYpNRhcL0EYWoSihfVCr3FvDB81ukMJY2GQE/szKN+OMY3EU/t3Wgx\n" \
    "jkzSswF07r51XgdIGn9w/xZchMB5hbgF/X++ZRGjD8ACtPhSNzkE1akxehi/oCr0\n" \
    "Epn3o0WC4zxe9Z2etciefC7IpJ5OCBRLbf1wbWsaY71k5h+3zvDyny67G7fyUIhz\n" \
    "ksLi4xaNmjICq44Y3ekQEe5+NauQrz4wlHrQMz2nZQ/1/I6eYs9HRCwBXbsdtTLS\n" \
    "R9I4LtD+gdwyah617jzV/OeBHRnDJELqYzmp\n"                             \
    "-----END CERTIFICATE-----\n"
#endif /* ifndef democonfigROOT_CA_PEM */

/**
 * @brief Event buffer.
 */
static OtaEventData_t eventBuffer;

/**
 * @brief Static handle for MQTT context.
 */
static MQTTContext_t xMQTTContext;

/**
 * @brief Static handle for Network context for HTTP connection.
 */
NetworkContext_t xNetworkContextHttp;

/**
 * @brief Static handle for Network context for MQTT connection.
 */
NetworkContext_t xNetworkContextMqtt;

/* The transport layer interface used by the HTTP Client library. */
TransportInterface_t xTransportInterfaceHttp;

/**
 * @brief Flag for HTTP connection.
 */
BaseType_t xIsHttpConnectionEstablished = pdFALSE;

/**
 * @brief The location of the path within the pre-signed URL.
 */
static const char * pcPath;

/**
 * @brief Static buffer used to hold MQTT messages being sent and received.
 */
static uint8_t ucSharedBuffer[ otaexampleNETWORK_BUFFER_SIZE ];

/**
 * @brief Global entry time into the application to use as a reference timestamp
 * in the #prvGetTimeMs function. #prvGetTimeMs will always return the difference
 * between the current time and the global entry time. This will reduce the chances
 * of overflow for the 32 bit unsigned integer used for holding the timestamp.
 */
static uint32_t ulGlobalEntryTimeMs;

/** @brief Static buffer used to hold MQTT messages being sent and received. */
static MQTTFixedBuffer_t xBuffer =
{
    ucSharedBuffer,
    otaexampleNETWORK_BUFFER_SIZE
};

/**
 * @brief The buffer passed to the OTA Agent from application while initializing.
 */
static OtaAppBuffer_t otaBuffer =
{
    .pUpdateFilePath    = updateFilePath,
    .updateFilePathsize = otaexampleMAX_FILE_PATH_SIZE,
    .pCertFilePath      = certFilePath,
    .certFilePathSize   = otaexampleMAX_FILE_PATH_SIZE,
    .pStreamName        = streamName,
    .streamNameSize     = otaexampleMAX_STREAM_NAME_SIZE,
    .pDecodeMemory      = decodeMem,
    .decodeMemorySize   = ( 1U << otaconfigLOG2_FILE_BLOCK_SIZE ),
    .pFileBitmap        = bitmap,
    .fileBitmapSize     = OTA_MAX_BLOCK_BITMAP_SIZE
};

/**
 * @brief Struct for firmware version.
 */
const AppVersion32_t appFirmwareVersion =
{
    .u.x.major = APP_VERSION_MAJOR,
    .u.x.minor = APP_VERSION_MINOR,
    .u.x.build = APP_VERSION_BUILD,
};

/*-----------------------------------------------------------*/

/**
 * @brief Connect to MQTT broker with reconnection retries.
 *
 * If connection fails, retry is attempted after a timeout.
 * Timeout value will exponentially increase until maximum
 * timeout value is reached or the number of attempts are exhausted.
 *
 * @param[out] pxNetworkContext The output parameter to return the created network context.
 *
 * @return pdFAIL on failure; pdPASS on successful TLS+TCP network connection.
 */
static BaseType_t prvConnectToServerWithBackoffRetries( NetworkContext_t * pNetworkContext );

/**
 * @brief The application callback function for getting the incoming publishes,
 * incoming acks, and ping responses reported from the MQTT library.
 *
 * @param[in] pxMQTTContext MQTT context pointer.
 * @param[in] pxPacketInfo Packet Info pointer for the incoming packet.
 * @param[in] pxDeserializedInfo Deserialized information from the incoming packet.
 */
static void prvEventCallback( MQTTContext_t * pxMQTTContext,
                              MQTTPacketInfo_t * pxPacketInfo,
                              MQTTDeserializedInfo_t * pxDeserializedInfo );

/*
 * Publish a message to the specified client/topic at the given QOS.
 */
static OtaErr_t mqttPublish( const char * const pacTopic,
                             uint16_t topicLen,
                             const char * pMsg,
                             uint32_t msgSize,
                             uint8_t qos );

/*
 * Subscribe to the topics.
 */
static OtaErr_t mqttSubscribe( const char * pTopicFilter,
                               uint16_t topicFilterLength,
                               uint8_t qos,
                               void * pCallback );

/*
 * Unsubscribe from the topics.
 */
static OtaErr_t mqttUnsubscribe( const char * pTopicFilter,
                                 uint16_t topicFilterLength,
                                 uint8_t qos );

/*-----------------------------------------------------------*/

static void prvEventCallback( MQTTContext_t * pxMQTTContext,
                              MQTTPacketInfo_t * pxPacketInfo,
                              MQTTDeserializedInfo_t * pxDeserializedInfo )
{
    configASSERT( pxMQTTContext != NULL );
    configASSERT( pxPacketInfo != NULL );
    configASSERT( pxDeserializedInfo != NULL );

    /* Handle incoming publish. The lower 4 bits of the publish packet
     * type is used for the dup, QoS, and retain flags. Hence masking
     * out the lower bits to check if the packet is publish. */
    if( ( pxPacketInfo->type & 0xF0U ) == MQTT_PACKET_TYPE_PUBLISH )
    {
        configASSERT( pxDeserializedInfo->pPublishInfo != NULL );
        /* Handle incoming publish. */
        SubscriptionManager_DispatchHandler( pxMQTTContext, pxDeserializedInfo->pPublishInfo );
    }
    else
    {
        /* Handle other packets. */
        switch( pxPacketInfo->type )
        {
            case MQTT_PACKET_TYPE_SUBACK:
                LogInfo( ( "Received SUBACK.\n\n" ) );
                break;

            case MQTT_PACKET_TYPE_UNSUBACK:
                LogInfo( ( "Received UNSUBACK.\n\n" ) );
                break;

            case MQTT_PACKET_TYPE_PINGRESP:

                /* Nothing to be done from application as library handles
                 * PINGRESP. */
                LogWarn( ( "PINGRESP should not be handled by the application "
                           "callback when using MQTT_ProcessLoop.\n\n" ) );
                break;

            case MQTT_PACKET_TYPE_PUBACK:
                LogInfo( ( "PUBACK received for packet id %u.\n\n",
                           pxDeserializedInfo->packetIdentifier ) );
                break;

            /* Any other packet type is invalid. */
            default:
                LogError( ( "Unknown packet type received:(%02x).\n\n",
                            pxPacketInfo->type ) );
        }
    }
}

/*-----------------------------------------------------------*/

static uint32_t prvGetTimeMs( void )
{
    TickType_t xTickCount = 0;
    uint32_t ulTimeMs = 0UL;

    /* Get the current tick count. */
    xTickCount = xTaskGetTickCount();

    /* Convert the ticks to milliseconds. */
    ulTimeMs = ( uint32_t ) xTickCount * MILLISECONDS_PER_TICK;

    /* Reduce ulGlobalEntryTimeMs from obtained time so as to always return the
     * elapsed time in the application. */
    ulTimeMs = ( uint32_t ) ( ulTimeMs - ulGlobalEntryTimeMs );

    return ulTimeMs;
}

static int32_t prvGenerateRandomNumber()
{
    uint32_t ulRandomNum;

    /* Use the PKCS11 module to generate a random number. */
    if( xPkcs11GenerateRandomNumber( ( uint8_t * ) &ulRandomNum,
                                     ( sizeof( ulRandomNum ) ) ) == pdPASS )
    {
        ulRandomNum = ( ulRandomNum & INT32_MAX );
    }
    else
    {
        /* Set the return value as negative to indicate failure. */
        ulRandomNum = -1;
    }

    return ( int32_t ) ulRandomNum;
}

/*-----------------------------------------------------------*/

static BaseType_t prvCreateMQTTConnectionWithBroker( MQTTContext_t * pxMQTTContext,
                                                     NetworkContext_t * pxNetworkContext )
{
    MQTTStatus_t xResult;
    MQTTConnectInfo_t xConnectInfo;
    bool xSessionPresent;
    TransportInterface_t xTransport;
    BaseType_t xStatus = pdFAIL;

    /* Fill in Transport Interface send and receive function pointers. */
    xTransport.pNetworkContext = pxNetworkContext;
    xTransport.send = SecureSocketsTransport_Send;
    xTransport.recv = SecureSocketsTransport_Recv;

    /* Initialize MQTT library. */
    xResult = MQTT_Init( pxMQTTContext, &xTransport, prvGetTimeMs, prvEventCallback, &xBuffer );
    configASSERT( xResult == MQTTSuccess );

    /* Some fields are not used in this demo so start with everything at 0. */
    ( void ) memset( ( void * ) &xConnectInfo, 0x00, sizeof( xConnectInfo ) );

    /* Start with a clean session i.e. direct the MQTT broker to discard any
     * previous session data. Also, establishing a connection with clean session
     * will ensure that the broker does not store any data when this client
     * gets disconnected. */
    xConnectInfo.cleanSession = true;

    /* The client identifier is used to uniquely identify this MQTT client to
     * the MQTT broker. In a production device the identifier can be something
     * unique, such as a device serial number. */
    xConnectInfo.pClientIdentifier = democonfigCLIENT_IDENTIFIER;
    xConnectInfo.clientIdentifierLength = ( uint16_t ) strlen( democonfigCLIENT_IDENTIFIER );

    /* Set MQTT keep-alive period. If the application does not send packets at an interval less than
     * the keep-alive period, the MQTT library will send PINGREQ packets. */
    xConnectInfo.keepAliveSeconds = otaexampleKEEP_ALIVE_TIMEOUT_SECONDS;

    /* Send MQTT CONNECT packet to broker. LWT is not used in this demo, so it
     * is passed as NULL. */
    xResult = MQTT_Connect( pxMQTTContext,
                            &xConnectInfo,
                            NULL,
                            otaexampleCONNACK_RECV_TIMEOUT_MS,
                            &xSessionPresent );

    if( xResult != MQTTSuccess )
    {
        LogError( ( "Failed to establish MQTT connection: Server=%s, MQTTStatus=%s",
                    democonfigMQTT_BROKER_ENDPOINT, MQTT_Status_strerror( xResult ) ) );
    }
    else
    {
        /* Successfully established and MQTT connection with the broker. */
        LogInfo( ( "An MQTT connection is established with %s.", democonfigMQTT_BROKER_ENDPOINT ) );
        xStatus = pdPASS;
    }

    return xStatus;
}

static BaseType_t prvConnectToServerWithBackoffRetries( NetworkContext_t * pxNetworkContext )
{
    ServerInfo_t xServerInfo = { 0 };
    SocketsConfig_t xSocketsConfig = { 0 };
    BaseType_t xStatus = pdPASS;
    TransportSocketStatus_t xNetworkStatus = TRANSPORT_SOCKET_STATUS_SUCCESS;
    BackoffAlgorithmStatus_t xBackoffAlgStatus = BackoffAlgorithmSuccess;
    BackoffAlgorithmContext_t xReconnectParams;
    uint16_t usNextRetryBackOff = 0U;

    /* Set the credentials for establishing a TLS connection. */
    /* Initializer server information. */
    xServerInfo.pHostName = democonfigMQTT_BROKER_ENDPOINT;
    xServerInfo.hostNameLength = strlen( democonfigMQTT_BROKER_ENDPOINT );
    xServerInfo.port = democonfigMQTT_BROKER_PORT;

    /* Configure credentials for TLS mutual authenticated session. */
    xSocketsConfig.enableTls = true;
    xSocketsConfig.pAlpnProtos = NULL;
    xSocketsConfig.maxFragmentLength = 0;
    xSocketsConfig.disableSni = false;
    xSocketsConfig.pRootCa = democonfigROOT_CA_PEM;
    xSocketsConfig.rootCaSize = sizeof( democonfigROOT_CA_PEM );
    xSocketsConfig.sendTimeoutMs = otaexampleTRANSPORT_SEND_RECV_TIMEOUT_MS;
    xSocketsConfig.recvTimeoutMs = otaexampleTRANSPORT_SEND_RECV_TIMEOUT_MS;

    /* Initialize reconnect attempts and interval. */
    BackoffAlgorithm_InitializeParams( &xReconnectParams,
                                       RETRY_BACKOFF_BASE_MS,
                                       RETRY_MAX_BACKOFF_DELAY_MS,
                                       RETRY_MAX_ATTEMPTS,
                                       prvGenerateRandomNumber );

    /* Attempt to connect to MQTT broker. If connection fails, retry after
     * a timeout. Timeout value will exponentially increase till maximum
     * attempts are reached.
     */
    do
    {
        /* Establish a TLS session with the MQTT broker. This example connects to
         * the MQTT broker as specified in democonfigMQTT_BROKER_ENDPOINT and
         * democonfigMQTT_BROKER_PORT at the top of this file. */
        LogInfo( ( "Creating a TLS connection to %s:%u.",
                   democonfigMQTT_BROKER_ENDPOINT,
                   democonfigMQTT_BROKER_PORT ) );
        /* Attempt to create a mutually authenticated TLS connection. */
        xNetworkStatus = SecureSocketsTransport_Connect( pxNetworkContext,
                                                         &xServerInfo,
                                                         &xSocketsConfig );

        if( xNetworkStatus != TRANSPORT_SOCKET_STATUS_SUCCESS )
        {
            /* Get back-off value (in milliseconds) for the next connection retry. */
            xBackoffAlgStatus = BackoffAlgorithm_GetNextBackoff( &xReconnectParams, &usNextRetryBackOff );
            configASSERT( xBackoffAlgStatus != BackoffAlgorithmRngFailure );

            if( xBackoffAlgStatus == BackoffAlgorithmRetriesExhausted )
            {
                LogError( ( "Connection to the broker failed, all attempts exhausted." ) );
                xStatus = pdFAIL;
            }
            else if( xBackoffAlgStatus == BackoffAlgorithmSuccess )
            {
                LogWarn( ( "Connection to the broker failed. Retrying connection after backoff delay." ) );
                vTaskDelay( pdMS_TO_TICKS( usNextRetryBackOff ) );

                LogInfo( ( "Retry attempt %lu out of maximum retry attempts %lu.",
                           ( xReconnectParams.attemptsDone + 1 ),
                           xReconnectParams.maxRetryAttempts ) );
            }
        }
    } while( ( xNetworkStatus != TRANSPORT_SOCKET_STATUS_SUCCESS ) && ( xBackoffAlgStatus == BackoffAlgorithmSuccess ) );

    return xStatus;
}

/*-----------------------------------------------------------*/

/**
 * @brief The OTA agent has completed the update job or it is in
 * self test mode. If it was accepted, we want to activate the new image.
 * This typically means we should reset the device to run the new firmware.
 * If now is not a good time to reset the device, it may be activated later
 * by your user code. If the update was rejected, just return without doing
 * anything and we will wait for another job. If it reported that we should
 * start test mode, normally we would perform some kind of system checks to
 * make sure our new firmware does the basic things we think it should do
 * but we will just go ahead and set the image as accepted for demo purposes.
 * The accept function varies depending on your platform. Refer to the OTA
 * PAL implementation for your platform in aws_ota_pal.c to see what it
 * does for you.
 *
 * @param[in] event Specify if this demo is running with the AWS IoT
 * MQTT server. Set this to `false` if using another MQTT server.
 * @return None.
 */
static void otaAppCallback( OtaJobEvent_t event )
{
    OtaErr_t err = OTA_ERR_UNINITIALIZED;

    /* OTA job is completed. so delete the MQTT and network connection. */
    if( event == OtaJobEventActivate )
    {
        LogInfo( ( "Received OtaJobEventActivate callback from OTA Agent." ) );

        /* OTA job is completed. so delete the network connection. */
        /*MQTT_Disconnect( &mqttContext ); */

        /* Activate the new firmware image. */
        OTA_ActivateNewImage();

        /* We should never get here as new image activation must reset the device.*/
        LogError( ( "New image activation failed." ) );

        for( ; ; )
        {
        }
    }
    else if( event == OtaJobEventFail )
    {
        LogInfo( ( "Received OtaJobEventFail callback from OTA Agent." ) );

        /* Nothing special to do. The OTA agent handles it. */
    }
    else if( event == OtaJobEventStartTest )
    {
        /* This demo just accepts the image since it was a good OTA update and networking
         * and services are all working (or we would not have made it this far). If this
         * were some custom device that wants to test other things before calling it OK,
         * this would be the place to kick off those tests before calling OTA_SetImageState()
         * with the final result of either accepted or rejected. */

        LogInfo( ( "Received OtaJobEventStartTest callback from OTA Agent." ) );
        err = OTA_SetImageState( OtaImageStateAccepted );

        if( err != OTA_ERR_NONE )
        {
            LogError( ( " Error! Failed to set image state as accepted." ) );
        }
    }
}

/*-----------------------------------------------------------*/

static void mqttDataCallback( MQTTContext_t * pContext,
                              MQTTPublishInfo_t * pPublishInfo )
{
    configASSERT( pPublishInfo != NULL );
    configASSERT( pContext != NULL );

    OtaEventData_t * pData;
    OtaEventMsg_t eventMsg = { 0 };

    LogInfo( ( "Received data message callback, size %d.\n\n", pPublishInfo->payloadLength ) );

    pData = &eventBuffer;

    if( pData != NULL )
    {
        memcpy( pData->data, pPublishInfo->pPayload, pPublishInfo->payloadLength );
        pData->dataLength = pPublishInfo->payloadLength;
        eventMsg.eventId = OtaAgentEventReceivedFileBlock;
        eventMsg.pEventData = pData;

        /* Send job document received event. */
        OTA_SignalEvent( &eventMsg );
    }
    else
    {
        LogError( ( "Error: No OTA data buffers available.\r\n" ) );
    }
}

/*-----------------------------------------------------------*/

static void mqttJobCallback( MQTTContext_t * pContext,
                             MQTTPublishInfo_t * pPublishInfo )
{
    configASSERT( pPublishInfo != NULL );
    configASSERT( pContext != NULL );

    OtaEventData_t * pData;
    OtaEventMsg_t eventMsg = { 0 };

    LogInfo( ( "Received job message callback, size %d.\n\n", pPublishInfo->payloadLength ) );

    pData = &eventBuffer;

    if( pData != NULL )
    {
        memcpy( pData->data, pPublishInfo->pPayload, pPublishInfo->payloadLength );
        pData->dataLength = pPublishInfo->payloadLength;
        eventMsg.eventId = OtaAgentEventReceivedJobDocument;
        eventMsg.pEventData = pData;

        /* Send job document received event. */
        OTA_SignalEvent( &eventMsg );
    }
    else
    {
        LogError( ( "Error: No OTA data buffers available.\r\n" ) );
    }
}

/*-----------------------------------------------------------*/

static OtaErr_t mqttSubscribe( const char * pTopicFilter,
                               uint16_t topicFilterLength,
                               uint8_t qos,
                               void * pCallback )
{
    OtaErr_t otaRet = OTA_ERR_NONE;

    int returnStatus = EXIT_SUCCESS;
    MQTTStatus_t mqttStatus;
    MQTTContext_t * pMqttContext = &xMQTTContext;
    MQTTSubscribeInfo_t pSubscriptionList[ 1 ];

    configASSERT( pMqttContext != NULL );
    configASSERT( pTopicFilter != NULL );
    configASSERT( topicFilterLength > 0 );

    /* Start with everything at 0. */
    ( void ) memset( ( void * ) pSubscriptionList, 0x00, sizeof( pSubscriptionList ) );

    /* This example subscribes to only one topic and uses QOS1. */
    pSubscriptionList[ 0 ].qos = qos;
    pSubscriptionList[ 0 ].pTopicFilter = pTopicFilter;
    pSubscriptionList[ 0 ].topicFilterLength = topicFilterLength;

    /* Send SUBSCRIBE packet. */
    mqttStatus = MQTT_Subscribe( pMqttContext,
                                 pSubscriptionList,
                                 sizeof( pSubscriptionList ) / sizeof( MQTTSubscribeInfo_t ),
                                 MQTT_GetPacketId( pMqttContext ) );

    if( mqttStatus != MQTTSuccess )
    {
        LogError( ( "Failed to send SUBSCRIBE packet to broker with error = %u.",
                    mqttStatus ) );

        otaRet = OTA_ERR_SUBSCRIBE_FAILED;
    }
    else
    {
        LogInfo( ( "SUBSCRIBE topic %.*s to broker.\n\n",
                   topicFilterLength,
                   pTopicFilter ) );

        otaRet = OTA_ERR_NONE;
    }

    /* Register callback to subscription manager. */
    SubscriptionManager_RegisterCallback( pTopicFilter, topicFilterLength, pCallback );

    return otaRet;
}

/*
 * Publish a message to the specified client/topic at the given QOS.
 */
static OtaErr_t mqttPublish( const char * const pacTopic,
                             uint16_t topicLen,
                             const char * pMsg,
                             uint32_t msgSize,
                             uint8_t qos )
{
    OtaErr_t otaRet = OTA_ERR_UNINITIALIZED;

    MQTTStatus_t mqttStatus = MQTTBadParameter;
    MQTTPublishInfo_t publishInfo;
    MQTTContext_t * pMqttContext = &xMQTTContext;

    publishInfo.pTopicName = pacTopic;
    publishInfo.topicNameLength = topicLen;
    publishInfo.qos = qos;
    publishInfo.pPayload = pMsg;
    publishInfo.payloadLength = msgSize;

    mqttStatus = MQTT_Publish( pMqttContext,
                               &publishInfo,
                               MQTT_GetPacketId( pMqttContext ) );

    if( mqttStatus != MQTTSuccess )
    {
        LogError( ( "Failed to send PUBLISH packet to broker with error = %u.", mqttStatus ) );

        otaRet = OTA_ERR_PUBLISH_FAILED;
    }
    else
    {
        LogInfo( ( "Sent PUBLISH packet to broker %.*s to broker.\n\n",
                   topicLen,
                   pacTopic ) );

        otaRet = OTA_ERR_NONE;
    }

    return otaRet;
}

static OtaErr_t mqttUnsubscribe( const char * pTopicFilter,
                                 uint16_t topicFilterLength,
                                 uint8_t qos )
{
    OtaErr_t otaRet = OTA_ERR_NONE;
    MQTTStatus_t mqttStatus;

    MQTTSubscribeInfo_t pSubscriptionList[ 1 ];
    MQTTContext_t * pMqttContext = &xMQTTContext;

    /* Start with everything at 0. */
    ( void ) memset( ( void * ) pSubscriptionList, 0x00, sizeof( pSubscriptionList ) );

    /* This example subscribes to and unsubscribes from only one topic
     * and uses QOS1. */
    pSubscriptionList[ 0 ].qos = qos;
    pSubscriptionList[ 0 ].pTopicFilter = pTopicFilter;
    pSubscriptionList[ 0 ].topicFilterLength = topicFilterLength;

    /* Send UNSUBSCRIBE packet. */
    mqttStatus = MQTT_Unsubscribe( pMqttContext,
                                   pSubscriptionList,
                                   sizeof( pSubscriptionList ) / sizeof( MQTTSubscribeInfo_t ),
                                   MQTT_GetPacketId( pMqttContext ) );

    if( mqttStatus != MQTTSuccess )
    {
        LogError( ( "Failed to send SUBSCRIBE packet to broker with error = %u.",
                    mqttStatus ) );

        otaRet = OTA_ERR_UNSUBSCRIBE_FAILED;
    }
    else
    {
        LogInfo( ( "SUBSCRIBE topic %.*s to broker.\n\n",
                   topicFilterLength,
                   pTopicFilter ) );

        otaRet = OTA_ERR_NONE;
    }

    return otaRet;
}

static BaseType_t prvConnectToServer( NetworkContext_t * pxNetworkContext,
                                      const char * pUrl )
{
    ServerInfo_t xServerInfo = { 0 };
    SocketsConfig_t xSocketsConfig = { 0 };
    BaseType_t xStatus = pdPASS;
    TransportSocketStatus_t xNetworkStatus = TRANSPORT_SOCKET_STATUS_SUCCESS;
    HTTPStatus_t xHTTPStatus = HTTPSuccess;

    /* The location of the host address within the pre-signed URL. */
    const char * pcAddress = NULL;

    /* Retrieve the address location and length from democonfigS3_PRESIGNED_GET_URL. */
    if( pUrl != NULL )
    {
        xHTTPStatus = getUrlAddress( pUrl,
                                     strlen( pUrl ),
                                     &pcAddress,
                                     &xServerHostLength );
    }

    xStatus = ( xHTTPStatus == HTTPSuccess ) ? pdPASS : pdFAIL;

    if( xStatus == pdPASS )
    {
        if( pUrl != NULL )
        {
            /* cServerHost should consist only of the host address located in
             * democonfigS3_PRESIGNED_GET_URL. */
            memcpy( cServerHost, pcAddress, xServerHostLength );
            cServerHost[ xServerHostLength ] = '\0';
        }

        /* Initializer server information. */
        xServerInfo.pHostName = cServerHost;
        xServerInfo.hostNameLength = xServerHostLength;
        xServerInfo.port = democonfigHTTPS_PORT;

        /* Configure credentials for TLS server-authenticated session. */
        xSocketsConfig.enableTls = true;
        xSocketsConfig.pAlpnProtos = NULL;
        xSocketsConfig.maxFragmentLength = 0;
        xSocketsConfig.disableSni = false;
        xSocketsConfig.pRootCa = democonfigBA_ROOT_CA_PEM;
        xSocketsConfig.rootCaSize = sizeof( democonfigBA_ROOT_CA_PEM );
        xSocketsConfig.sendTimeoutMs = otaexampleTRANSPORT_SEND_RECV_TIMEOUT_MS;
        xSocketsConfig.recvTimeoutMs = otaexampleTRANSPORT_SEND_RECV_TIMEOUT_MS;

        /* Establish a TLS session with the HTTP server. This example connects
         * to the server host located in democonfigPRESIGNED_GET_URL and
         * democonfigHTTPS_PORT in demo_config.h. */
        LogInfo( ( "Establishing a TLS session with %s:%d.",
                   cServerHost,
                   democonfigHTTPS_PORT ) );

        /* Attempt to create a server-authenticated TLS connection. */
        xNetworkStatus = SecureSocketsTransport_Connect( pxNetworkContext,
                                                         &xServerInfo,
                                                         &xSocketsConfig );

        if( xNetworkStatus != TRANSPORT_SOCKET_STATUS_SUCCESS )
        {
            xStatus = pdFAIL;
        }
    }

    return xStatus;
}

static void prvDisconnectFromServer( NetworkContext_t * pxNetworkContext )
{
    TransportSocketStatus_t xNetworkStatus = TRANSPORT_SOCKET_STATUS_SUCCESS;

    /* Close the network connection to clean up any system resources that the
     * demo may have consumed. */

    if( xIsHttpConnectionEstablished == pdTRUE )
    {
        /* Close the network connection.  */
        xNetworkStatus = SecureSocketsTransport_Disconnect( &xNetworkContextHttp );

        if( xNetworkStatus != TRANSPORT_SOCKET_STATUS_SUCCESS )
        {
            LogError( ( "SecureSocketsTransport_Disconnect() failed to close the network connection. "
                        "StatusCode=%d.", ( int ) xNetworkStatus ) );
        }
    }
}

static OtaErr_t httpInit( const char * pUrl )
{
    /* OTA lib return error code. */
    OtaErr_t ret = OTA_ERR_UNINITIALIZED;

    /* Return value from libraries. */
    int32_t returnStatus = EXIT_SUCCESS;

    BaseType_t xRet = pdFAIL;

    size_t xPathLen = 0;

    /* HTTPS Client library return status. */
    HTTPStatus_t xHTTPStatus = HTTPSuccess;

    /* Establish HTTPs connection */
    LogInfo( ( "Performing TLS handshake on top of the TCP connection." ) );
    /**************************** Connect. ******************************/

    /* Establish TLS connection on top of TCP connection using Secure Sockets. */

    /* Attempt to connect to S3. If connection fails, retry after a timeout.
     * The timeout value will be exponentially increased until either the
     * maximum number of attempts or the maximum timeout value is reached.
     * The function returns pdFAIL if a TCP connection with the broker
     * cannot be established  after the configured number of attempts. */
    xRet = prvConnectToServer( &xNetworkContextHttp, pUrl );

    if( xRet == pdPASS )
    {
        /* Set a flag indicating that a TLS connection exists. */
        xIsHttpConnectionEstablished = pdTRUE;

        /* Define the transport interface. */
        xTransportInterfaceHttp.pNetworkContext = &xNetworkContextHttp;
        xTransportInterfaceHttp.send = SecureSocketsTransport_Send;
        xTransportInterfaceHttp.recv = SecureSocketsTransport_Recv;
    }
    else
    {
        /* Log an error to indicate connection failure after all
         * reconnect attempts are over. */
        LogError( ( "Failed to connect to HTTP server %s.",
                    cServerHost ) );
    }

    if( xRet == pdPASS )
    {
        /* Retrieve the path location from democonfigS3_PRESIGNED_GET_URL. This
         * function returns the length of the path without the query into
         * xPathLen, which is left unused in this demo. */
        xHTTPStatus = getUrlPath( pUrl,
                                  strlen( pUrl ),
                                  &pcPath,
                                  &xPathLen );

        xRet = ( xHTTPStatus == HTTPSuccess ) ? pdPASS : pdFAIL;
    }

    return ( xRet == pdPASS ) ? OTA_ERR_NONE : OTA_ERR_HTTP_INIT_FAILED;
}

static OtaErr_t httpRequest( uint32_t rangeStart,
                             uint32_t rangeEnd )
{
    /* Return value of this method. */
    int32_t returnStatus = EXIT_SUCCESS;

    /* OTA lib return error code. */
    OtaErr_t ret = OTA_ERR_UNINITIALIZED;

    OtaEventData_t * pData = &eventBuffer;
    OtaEventMsg_t eventMsg = { 0 };

    /* Configurations of the initial request headers that are passed to
     * #HTTPClient_InitializeRequestHeaders. */
    HTTPRequestInfo_t requestInfo;
    /* Represents a response returned from an HTTP server. */
    HTTPResponse_t response;
    /* Represents header data that will be sent in an HTTP request. */
    HTTPRequestHeaders_t requestHeaders;

    /* Return value of all methods from the HTTP Client library API. */
    HTTPStatus_t httpStatus = HTTPSuccess;

    /* Initialize all HTTP Client library API structs to 0. */
    ( void ) memset( &requestInfo, 0, sizeof( requestInfo ) );
    ( void ) memset( &response, 0, sizeof( response ) );
    ( void ) memset( &requestHeaders, 0, sizeof( requestHeaders ) );

    /* Initialize the request object. */
    requestInfo.pHost = cServerHost;
    requestInfo.hostLen = xServerHostLength;
    requestInfo.pMethod = HTTP_METHOD_GET;
    requestInfo.methodLen = sizeof( HTTP_METHOD_GET ) - 1;
    requestInfo.pPath = pcPath;
    requestInfo.pathLen = strlen( pcPath );

    /* Set "Connection" HTTP header to "keep-alive" so that multiple requests
     * can be sent over the same established TCP connection. */
    requestInfo.reqFlags = HTTP_REQUEST_KEEP_ALIVE_FLAG;

    /* Set the buffer used for storing request headers. */
    requestHeaders.pBuffer = userBuffer;
    requestHeaders.bufferLen = USER_BUFFER_LENGTH;

    httpStatus = HTTPClient_InitializeRequestHeaders( &requestHeaders,
                                                      &requestInfo );

    HTTPClient_AddRangeHeader( &requestHeaders, rangeStart, rangeEnd );

    if( httpStatus == HTTPSuccess )
    {
        /* Initialize the response object. The same buffer used for storing
         * request headers is reused here. */
        response.pBuffer = userBuffer;
        response.bufferLen = USER_BUFFER_LENGTH;

        /* Send the request and receive the response. */
        httpStatus = HTTPClient_Send( &xTransportInterfaceHttp,
                                      &requestHeaders,
                                      NULL,
                                      0,
                                      &response,
                                      0 );
    }
    else
    {
        LogError( ( "Failed to initialize HTTP request headers: Error=%s.",
                    HTTPClient_strerror( httpStatus ) ) );
    }

    if( httpStatus != HTTPSuccess )
    {
        if( httpStatus == HTTPNetworkError )
        {
            /* Reconnect to server. */
            prvConnectToServer( &xNetworkContextHttp, NULL );

            /* Send job document request event. */
            eventMsg.eventId = OtaAgentEventRequestFileBlock;
            OTA_SignalEvent( &eventMsg );

            ret = OTA_ERR_NONE;
        }
        else
        {
            ret = OTA_ERR_HTTP_REQUEST_FAILED;
        }
    }
    else
    {
        /* Get the data from response buffer. */
        memcpy( pData->data, response.pBody, response.bodyLen );
        pData->dataLength = response.bodyLen;

        /* Send job document received event. */
        eventMsg.eventId = OtaAgentEventReceivedFileBlock;
        eventMsg.pEventData = pData;
        OTA_SignalEvent( &eventMsg );

        ret = OTA_ERR_NONE;
    }

    return returnStatus;
}

static OtaErr_t httpDeinit( void )
{
    /* Disconnect from server. */
    prvDisconnectFromServer( &xNetworkContextHttp );

    return OTA_ERR_NONE;
}

/*-----------------------------------------------------------*/

static void setOtaInterfaces( OtaInterfaces_t * pOtaInterfaces )
{
    configASSERT( pOtaInterfaces != NULL );

    /* Initialize OTA library OS Interface. */
    pOtaInterfaces->os.event.init = OtaInitEvent_FreeRTOS;
    pOtaInterfaces->os.event.send = OtaSendEvent_FreeRTOS;
    pOtaInterfaces->os.event.recv = OtaReceiveEvent_FreeRTOS;
    pOtaInterfaces->os.event.deinit = OtaDeinitEvent_FreeRTOS;
    pOtaInterfaces->os.timer.start = OtaStartTimer_FreeRTOS;
    pOtaInterfaces->os.timer.stop = OtaStopTimer_FreeRTOS;
    pOtaInterfaces->os.timer.delete = OtaDeleteTimer_FreeRTOS;
    pOtaInterfaces->os.mem.malloc = Malloc_FreeRTOS;
    pOtaInterfaces->os.mem.free = Free_FreeRTOS;

    /* Initialize the OTA library MQTT Interface.*/
    pOtaInterfaces->mqtt.subscribe = mqttSubscribe;
    pOtaInterfaces->mqtt.publish = mqttPublish;
    pOtaInterfaces->mqtt.unsubscribe = mqttUnsubscribe;
    pOtaInterfaces->mqtt.jobCallback = mqttJobCallback;
    pOtaInterfaces->mqtt.dataCallback = mqttDataCallback;

    /* Initialize the OTA library HTTP Interface.*/
    pOtaInterfaces->http.init = httpInit;
    pOtaInterfaces->http.request = httpRequest;
    pOtaInterfaces->http.deinit = httpDeinit;

    /* Initialize the OTA library PAL Interface.*/
    pOtaInterfaces->pal.getPlatformImageState = prvPAL_GetPlatformImageState;
    pOtaInterfaces->pal.setPlatformImageState = prvPAL_SetPlatformImageState;
    pOtaInterfaces->pal.writeBlock = prvPAL_WriteBlock;
    pOtaInterfaces->pal.activate = prvPAL_ActivateNewImage;
    pOtaInterfaces->pal.closeFile = prvPAL_CloseFile;
    pOtaInterfaces->pal.reset = prvPAL_ResetDevice;
    pOtaInterfaces->pal.abort = prvPAL_Abort;
    pOtaInterfaces->pal.createFile = prvPAL_CreateFileForRx;
}

static BaseType_t prvEstablishConnection( void )
{
    BaseType_t xRet = pdFAIL;

    /* Attempt to establish TLS session with MQTT broker. If connection fails,
     * retry after a timeout. Timeout value will be exponentially increased until
     * the maximum number of attempts are reached or the maximum timeout value is reached.
     * The function returns a failure status if the TLS over TCP connection cannot be established
     * to the broker after the configured number of attempts. */
    xRet = prvConnectToServerWithBackoffRetries( &xNetworkContextMqtt );

    if( xRet == pdPASS )
    {
        /* Sends an MQTT Connect packet over the already established TLS connection,
         * and waits for connection acknowledgment (CONNACK) packet. */
        LogInfo( ( "Creating an MQTT connection to %s.", democonfigMQTT_BROKER_ENDPOINT ) );
        xRet = prvCreateMQTTConnectionWithBroker( &xMQTTContext, &xNetworkContextMqtt );
    }

    return xRet;
}
static TransportSocketStatus_t prvDisconnect( void )
{
    /* Transport socket return status. */
    TransportSocketStatus_t xNetworkStatus;

    /* Disconnect from broker. */
    LogInfo( ( "Disconnecting the MQTT connection with %s.", democonfigMQTT_BROKER_ENDPOINT ) );
    MQTT_Disconnect( &xMQTTContext );

    /* Close the network connection. */
    xNetworkStatus = SecureSocketsTransport_Disconnect( &xNetworkContextMqtt );

    if( xNetworkStatus != TRANSPORT_SOCKET_STATUS_SUCCESS )
    {
        LogError( ( "SecureSocketsTransport_Disconnect() failed to close the network connection. "
                    "StatusCode=%d.", ( int ) xNetworkStatus ) );
    }

    return xNetworkStatus;
}

/*-----------------------------------------------------------*/

static int prvStartOTADemo( void )
{
    /* Status indicating a successful demo or not. */
    int32_t returnStatus = EXIT_SUCCESS;

    /* FreeRTOS APIs return status. */
    BaseType_t xRet = pdFAIL;

    /* coreMQTT library return status. */
    MQTTStatus_t mqttStatus = MQTTSuccess;

    /* OTA library return status. */
    OtaErr_t otaRet = OTA_ERR_NONE;

    /* OTA Agent state returned from calling OTA_GetAgentState.*/
    OtaState_t state = OtaAgentStateStopped;

    /* OTA event message used for sending event to OTA Agent.*/
    OtaEventMsg_t eventMsg = { 0 };

    /* OTA Agent thread handle.*/
    TaskHandle_t xOtaTaskHandle = NULL;

    /* OTA interface context required for library interface functions.*/
    OtaInterfaces_t otaInterfaces;

    BaseType_t xIsConnectionEstablished = pdFALSE;

    /* Set OTA Library interfaces.*/
    setOtaInterfaces( &otaInterfaces );

    /****************************** Init OTA Library. ******************************/

    if( ( otaRet = OTA_AgentInit( &otaBuffer,
                                  &otaInterfaces,
                                  ( const uint8_t * ) ( democonfigCLIENT_IDENTIFIER ),
                                  otaAppCallback ) ) != OTA_ERR_NONE )
    {
        LogError( ( "Failed to initialize OTA Agent, exiting = %u.",
                    otaRet ) );

        returnStatus = EXIT_FAILURE;
    }

    /****************************** Create OTA Task. ******************************/

    if( otaRet == OTA_ERR_NONE )
    {
        if( ( xRet = xTaskCreate( otaAgentTask,
                                  "OTA Agent Task",
                                  otaexampleSTACK_SIZE,
                                  NULL,
                                  tskIDLE_PRIORITY,
                                  &xOtaTaskHandle ) ) != pdPASS )
        {
            LogError( ( "Failed to start OTA task: "
                        ",errno=%d",
                        xRet ) );

            returnStatus = EXIT_FAILURE;
        }
    }

    /***************************Start OTA demo loop. ******************************/

    if( xRet == pdPASS )
    {
        /*
         * Wait forever for OTA traffic but allow other tasks to run and output
         * statistics only once per second. */
        while( ( ( state = OTA_GetAgentState() ) != OtaAgentStateStopped ) )
        {
            if( xIsConnectionEstablished != pdTRUE )
            {
                xRet = prvEstablishConnection();

                if( xRet == pdPASS )
                {
                    xIsConnectionEstablished = pdTRUE;

                    if( state == OtaAgentStateSuspended )
                    {
                        /* Resume OTA operations. */
                        OTA_Resume();
                    }
                    else
                    {
                        /* Send start event to OTA Agent.*/
                        eventMsg.eventId = OtaAgentEventStart;
                        OTA_SignalEvent( &eventMsg );
                    }
                }
            }

            if( xIsConnectionEstablished == pdTRUE )
            {
                /* Loop to receive packet from transport interface. */
                mqttStatus = MQTT_ProcessLoop( &xMQTTContext, otaexampleTASK_DELAY_MS );

                if( mqttStatus == MQTTSuccess )
                {
                    LogInfo( ( " Received: %u   Queued: %u   Processed: %u   Dropped: %u",
                               OTA_GetPacketsReceived(),
                               OTA_GetPacketsQueued(),
                               OTA_GetPacketsProcessed(),
                               OTA_GetPacketsDropped() ) );
                }
                else
                {
                    LogError( ( "MQTT_ProcessLoop returned with status = %u.",
                                mqttStatus ) );

                    /* Discoonnect from broker and close connection. */
                    prvDisconnect();

                    xIsConnectionEstablished = pdFALSE;

                    /* Suspend OTA operations. */
                    otaRet = OTA_Suspend();

                    if( otaRet != OTA_ERR_NONE )
                    {
                        LogError( ( "OTA failed to suspend. "
                                    "StatusCode=%d.", otaRet ) );
                    }
                }
            }
        }

        if( xOtaTaskHandle != NULL )
        {
            vTaskDelete( xOtaTaskHandle );
            returnStatus = EXIT_SUCCESS;
        }
    }

    return returnStatus;
}

/**
 * @brief The function that runs the OTA demo, called by the demo runner.
 *
 * @param[in] awsIotMqttMode Specify if this demo is running with the AWS IoT
 * MQTT server. Set this to `false` if using another MQTT server.
 * @param[in] pIdentifier NULL-terminated MQTT client identifier.
 * @param[in] pNetworkServerInfo Passed to the MQTT connect function when
 * establishing the MQTT connection.
 * @param[in] pNetworkCredentialInfo Passed to the MQTT connect function when
 * establishing the MQTT connection.
 * @param[in] pNetworkInterface The network interface to use for this demo.
 *
 * @return `EXIT_SUCCESS` if the demo completes successfully; `EXIT_FAILURE` otherwise.
 */
int vStartOTAUpdateDemoTask( bool awsIotMqttMode,
                             const char * pIdentifier,
                             void * pNetworkServerInfo,
                             void * pNetworkCredentialInfo,
                             const IotNetworkInterface_t * pNetworkInterface )
{
    /* Remove compiler warnings about unused parameters. */
    ( void ) awsIotMqttMode;
    ( void ) pIdentifier;
    ( void ) pNetworkServerInfo;
    ( void ) pNetworkCredentialInfo;
    ( void ) pNetworkInterface;

    /* Return error status. */
    int32_t returnStatus = EXIT_FAILURE;

    /************************* Start OTA demo. ****************************/

    returnStatus = prvStartOTADemo();

    return returnStatus;
}
