/*
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
 */

/**
 * @file ota_demo_core_http.c
 * @brief OTA update example using coreMQTT and coreHTTP.
 */

/* Standard includes. */
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>

#include "aws_demo_config.h"

#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"

#include "iot_network.h"

/* MQTT include. */
#include "core_mqtt.h"

/* Retry utilities include. */
#include "backoff_algorithm.h"

/* HTTP include. */
#include "core_http_client.h"

/* Include PKCS11 helper for random number generation. */
#include "pkcs11_helpers.h"

/* Common HTTP demo utilities. */
#include "http_demo_utils.h"

/*Include backoff algorithm header for retry logic.*/
#include "backoff_algorithm.h"

/* Transport interface include. */
#include "transport_interface.h"

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

/* OTA Library Interface include. */
#include "ota_os_freertos.h"
#include "ota_mqtt_interface.h"


/* Helper functions such as subscription management. */
#include "ota_demo_helpers.h"

/* PAL abstraction layer APIs. */
#include "ota_pal.h"


/* Includes the OTA Application version number. */
#include "ota_appversion32.h"

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

#ifndef democonfigHTTPS_ROOT_CA_PEM
    #define democonfigHTTPS_ROOT_CA_PEM                                  \
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
#endif /* ifndef democonfigHTTPS_ROOT_CA_PEM */

/**
 * @brief AWS IoT Core server port number for HTTPS connections.
 *
 * For this demo, an X.509 certificate is used to verify the client.
 *
 * @note Port 443 requires use of the ALPN TLS extension with the ALPN protocol
 * name being x-amzn-http-ca. When using port 8443, ALPN is not required.
 */
#ifndef democonfigHTTPS_PORT
    #define democonfigHTTPS_PORT    443
#endif

/**
 * @brief Transport timeout in milliseconds for transport send and receive.
 */
#define otaexampleTRANSPORT_SEND_RECV_TIMEOUT_MS    ( 1000U )

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
#define RETRY_BACKOFF_BASE_MS               ( 500U )

/**
 * @brief ALPN (Application-Layer Protocol Negotiation) protocol name for AWS IoT MQTT.
 *
 * This will be used if the AWS_MQTT_PORT is configured as 443 for AWS IoT MQTT broker.
 * Please see more details about the ALPN protocol for AWS IoT MQTT endpoint
 * in the link below.
 * https://aws.amazon.com/blogs/iot/mqtt-with-tls-client-authentication-on-port-443-why-it-is-useful-and-how-it-works/
 */
#define AWS_IOT_MQTT_ALPN                   "\x0ex-amzn-mqtt-ca"

/**
 * @brief Length of ALPN protocol name.
 */
#define AWS_IOT_MQTT_ALPN_LENGTH            ( ( uint16_t ) ( sizeof( AWS_IOT_MQTT_ALPN ) - 1 ) )

/**
 * @brief Length of MQTT server host name.
 */
#define AWS_IOT_ENDPOINT_LENGTH             ( ( uint16_t ) ( sizeof( AWS_IOT_ENDPOINT ) - 1 ) )

/**
 * @brief Length of client identifier.
 */
#define CLIENT_IDENTIFIER_LENGTH            ( ( uint16_t ) ( sizeof( CLIENT_IDENTIFIER ) - 1 ) )

/**
 * @brief Transport timeout in milliseconds for transport send and receive.
 */
#define TRANSPORT_SEND_RECV_TIMEOUT_MS      ( 500U )

/**
 * @brief Timeout for receiving CONNACK packet in milli seconds.
 */
#define CONNACK_RECV_TIMEOUT_MS             ( 2000U )

/**
 * @brief The maximum time interval in seconds which is allowed to elapse
 * between two Control Packets.
 *
 * It is the responsibility of the Client to ensure that the interval between
 * Control Packets being sent does not exceed the this Keep Alive value. In the
 * absence of sending any other Control Packets, the Client MUST send a
 * PINGREQ Packet.
 */
#define MQTT_KEEP_ALIVE_INTERVAL_SECONDS    ( 60U )

/**
 * @brief Timeout for MQTT_ProcessLoop function in milliseconds.
 */
#define MQTT_PROCESS_LOOP_TIMEOUT_MS        ( 100U )

/**
 * @brief Interval between process loop  in milliseconds. This interval unblocks
 * any other threads waiting to perform an MQTT operation. This interval should be
 * short enough so that MQTT receive loop can execute almost quickly but still let
 * other thread not starve for MQTT operation to complete.
 */
#define MQTT_PROCESS_LOOP_INTERVAL_MS       ( 5U )

/**
 * @brief The delay used in the main OTA Demo task loop to periodically output the OTA
 * statistics like number of packets received, dropped, processed and queued per connection.
 */
#define OTA_EXAMPLE_TASK_DELAY_MS           ( 1000U )


/**
 * @brief The timeout for waiting for the agent to get suspended after closing the
 * connection.
 */
#define OTA_SUSPEND_TIMEOUT_MS                   ( 5000U )

/**
 * @brief The timeout for waiting before exiting the OTA demo.
 */
#define OTA_DEMO_EXIT_TIMEOUT_MS                 ( 3000U )

/**
 * @brief The maximum size of the file paths used in the demo.
 */
#define OTA_MAX_FILE_PATH_SIZE                   ( 260U )

/**
 * @brief The maximum size of the stream name required for downloading update file
 * from streaming service.
 */
#define OTA_MAX_STREAM_NAME_SIZE                 ( 128U )

/**
 * @brief The maximum back-off delay (in milliseconds) for retrying connection to server.
 */
#define CONNECTION_RETRY_MAX_BACKOFF_DELAY_MS    ( 5000U )

/**
 * @brief The base back-off delay (in milliseconds) to use for connection retry attempts.
 */
#define CONNECTION_RETRY_BACKOFF_BASE_MS         ( 500U )

/**
 * @brief Number of milliseconds in a second.
 */
#define NUM_MILLISECONDS_IN_SECOND               ( 1000U )

/**
 * @brief Maximum size of the url.
 */
#define OTA_MAX_URL_SIZE                         ( 2048U )

/**
 * @brief Maximum size of the auth scheme.
 */
#define OTA_MAX_AUTH_SCHEME_SIZE                 ( 2048U )

/**
 * @brief Size of the network buffer to receive the MQTT message.
 *
 * The largest message size is data size from the AWS IoT streaming service,
 * otaconfigFILE_BLOCK_SIZE + extra for headers.
 */

#define OTA_NETWORK_BUFFER_SIZE          ( otaconfigFILE_BLOCK_SIZE + OTA_MAX_URL_SIZE + 128 )

/**
 * @brief The maximum number of retries for connecting to server.
 */
#define CONNECTION_RETRY_MAX_ATTEMPTS    ( 5U )

/**
 * @brief The maximum size of the HTTP header.
 */
#define HTTP_HEADER_SIZE_MAX             ( 1024U )

/* HTTP buffers used for http request and response. */
#define HTTP_USER_BUFFER_LENGTH          ( otaconfigFILE_BLOCK_SIZE + HTTP_HEADER_SIZE_MAX )

/**
 * @brief The common prefix for all OTA topics.
 */
#define OTA_TOPIC_PREFIX                 "$aws/things/"

/**
 * @brief The string used for jobs topics.
 */
#define OTA_TOPIC_JOBS                   "jobs"

/**
 * @brief The string used for streaming service topics.
 */
#define OTA_TOPIC_STREAM                 "streams"

/**
 * @brief The length of #OTA_TOPIC_PREFIX
 */
#define OTA_TOPIC_PREFIX_LENGTH          ( ( uint16_t ) ( sizeof( OTA_TOPIC_PREFIX ) - 1U ) )

/**
 * @brief Stack size required for OTA agent task.
 */
#define OTA_AGENT_TASK_STACK_SIZE        ( 6000U )

/**
 * @brief Stack size required for OTA agent task.
 */
#define OTA_AGENT_TASK_PRIORITY          ( democonfigDEMO_PRIORITY )

/**
 * @brief Milliseconds per second.
 */
#define MILLISECONDS_PER_SECOND          ( 1000U )

/**
 * @brief Milliseconds per FreeRTOS tick.
 */
#define MILLISECONDS_PER_TICK            ( MILLISECONDS_PER_SECOND / configTICK_RATE_HZ )

/**
 * @brief HTTP response codes used in this demo.
 */
#define HTTP_RESPONSE_PARTIAL_CONTENT    ( 206 )
#define HTTP_RESPONSE_BAD_REQUEST        ( 400 )
#define HTTP_RESPONSE_FORBIDDEN          ( 403 )
#define HTTP_RESPONSE_NOT_FOUND          ( 404 )

/**
 * @brief Configure application version.
 */

/**
 * @brief Network connection context used in this demo for MQTT connection.
 */
static NetworkContext_t networkContextMqtt;

/**
 * @brief Network connection context used for HTTP connection.
 */
static NetworkContext_t networkContextHttp;


/**
 * @brief The host address string extracted from the pre-signed URL.
 *
 * @note S3_PRESIGNED_GET_URL_LENGTH is set as the array length here as the
 * length of the host name string cannot exceed this value.
 */
static char serverHost[ 256 ];

/**
 * @brief A buffer used in the demo for storing HTTP request headers and
 * HTTP response headers and body.
 *
 * @note This demo shows how the same buffer can be re-used for storing the HTTP
 * response after the HTTP request is sent out. However, the user can also
 * decide to use separate buffers for storing the HTTP request and response.
 */
static uint8_t httpUserBuffer[ HTTP_USER_BUFFER_LENGTH ];

/* The transport layer interface used by the HTTP Client library. */

TransportInterface_t transportInterfaceHttp;

/**
 * @brief MQTT connection context used in this demo.
 */
static MQTTContext_t mqttContext;

/**
 * @brief Keep a flag for indicating if the MQTT connection is alive.
 */
static bool mqttSessionEstablished = false;

/**
 * @brief Mutex for synchronizing coreMQTT API calls.
 */
static SemaphoreHandle_t xMqttMutex;

/**
 * @brief Semaphore for acknowledgment from MQTT packet.
 */
static SemaphoreHandle_t xMqttAckSem;

/**
 * @brief The host address string extracted from the pre-signed URL.
 *
 * @note S3_PRESIGNED_GET_URL_LENGTH is set as the array length here as the
 * length of the host name string cannot exceed this value.
 */
static char serverHost[ 256 ];

/**
 * @brief The length of the host address found in the pre-signed URL.
 */
static size_t serverHostLength;

/**
 * @brief Semaphore for synchronizing buffer operations.
 */
static SemaphoreHandle_t xBufferSemaphore;

/**
 * @brief Enum for type of OTA messages received.
 */
typedef enum OtaMessageType
{
    OtaMessageTypeJob = 0,
    OtaMessageTypeStream,
    OtaNumOfMessageType
} OtaMessageType_t;

/**
 * @brief The network buffer must remain valid when OTA library task is running.
 */
static uint8_t otaNetworkBuffer[ OTA_NETWORK_BUFFER_SIZE ];

/**
 * @brief The location of the path within the pre-signed URL.
 */
static const char * pPath;

/**
 * @brief Update File path buffer.
 */
uint8_t updateFilePath[ OTA_MAX_FILE_PATH_SIZE ];

/**
 * @brief Certificate File path buffer.
 */
uint8_t certFilePath[ OTA_MAX_FILE_PATH_SIZE ];

/**
 * @brief Stream name buffer.
 */
uint8_t streamName[ OTA_MAX_STREAM_NAME_SIZE ];

/**
 * @brief Decode memory.
 */
uint8_t decodeMem[ otaconfigFILE_BLOCK_SIZE ];

/**
 * @brief Bitmap memory.
 */
uint8_t bitmap[ OTA_MAX_BLOCK_BITMAP_SIZE ];

/**
 * @brief Certificate File path buffer.
 */
uint8_t updateUrl[ OTA_MAX_URL_SIZE ];

/**
 * @brief Auth scheme buffer.
 */
uint8_t authScheme[ OTA_MAX_URL_SIZE ];

/**
 * @brief Event buffer.
 */
static OtaEventData_t eventBuffer[ otaconfigMAX_NUM_OTA_DATA_BUFFERS ];

/**
 * @brief Global entry time into the application to use as a reference timestamp
 * in the #prvGetTimeMs function. #prvGetTimeMs will always return the difference
 * between the current time and the global entry time. This will reduce the chances
 * of overflow for the 32 bit unsigned integer used for holding the timestamp.
 */
static uint32_t ulGlobalEntryTimeMs;

/**
 * @brief The buffer passed to the OTA Agent from application while initializing.
 */
static OtaAppBuffer_t otaBuffer =
{
    .pUpdateFilePath    = updateFilePath,
    .updateFilePathsize = OTA_MAX_FILE_PATH_SIZE,
    .pCertFilePath      = certFilePath,
    .certFilePathSize   = OTA_MAX_FILE_PATH_SIZE,
    .pDecodeMemory      = decodeMem,
    .decodeMemorySize   = otaconfigFILE_BLOCK_SIZE,
    .pFileBitmap        = bitmap,
    .fileBitmapSize     = OTA_MAX_BLOCK_BITMAP_SIZE,
    .pUrl               = updateUrl,
    .urlSize            = OTA_MAX_URL_SIZE,
    .pAuthScheme        = authScheme,
    .authSchemeSize     = OTA_MAX_AUTH_SCHEME_SIZE
};

/*-----------------------------------------------------------*/

/**
 * @brief Retry logic to establish a connection to the server.
 *
 * If the connection fails, keep retrying with exponentially increasing
 * timeout value, until max retries, max timeout or successful connect.
 *
 * @param[in] pNetworkContext Network context to connect on.
 * @return int pdFALSE if connection failed after retries.
 */
static BaseType_t prvConnectToServerWithBackoffRetries( NetworkContext_t * pNetworkContext );

/**
 * @brief Sends an MQTT CONNECT packet over the already connected TCP socket.
 *
 * @param[in] pMqttContext MQTT context pointer.
 * @param[in] createCleanSession Creates a new MQTT session if true.
 * If false, tries to establish the existing session if there was session
 * already present in broker.
 * @param[out] pSessionPresent Session was already present in the broker or not.
 * Session present response is obtained from the CONNACK from broker.
 *
 * @return pdPASS if an MQTT session is established;
 * EXIT_FAILURE otherwise.
 */
static BaseType_t establishMqttSession( MQTTContext_t * pMqttContext );

/**
 * @brief Publish message to a topic.
 *
 * This function publishes a message to a given topic & QoS.
 *
 * @param[in] pTopic Mqtt topic filter.
 *
 * @param[in] topicLen Length of the topic filter.
 *
 * @param[in] pMsg Message to publish.
 *
 * @param[in] msgSize Message size.
 *
 * @param[in] qos Quality of Service
 *
 * @return OtaMqttSuccess if success , other error code on failure.
 */
static OtaMqttStatus_t mqttPublish( const char * const pTopic,
                                    uint16_t topicLen,
                                    const char * pMsg,
                                    uint32_t msgSize,
                                    uint8_t qos );

/**
 * @brief Subscribe to the Mqtt topics.
 *
 * This function subscribes to the Mqtt topics with the Quality of service
 * received as parameter. This function also registers a callback for the
 * topicfilter.
 *
 * @param[in] pTopicFilter Mqtt topic filter.
 *
 * @param[in] topicFilterLength Length of the topic filter.
 *
 * @param[in] qos Quality of Service
 *
 * @param[in] callback Callback to be registered.
 *
 * @return OtaMqttSuccess if success , other error code on failure.
 */
static OtaMqttStatus_t mqttSubscribe( const char * pTopicFilter,
                                      uint16_t topicFilterLength,
                                      uint8_t qos );

/**
 * @brief Unsubscribe to the Mqtt topics.
 *
 * This function unsubscribes to the Mqtt topics with the Quality of service
 * received as parameter.
 *
 * @param[in] pTopicFilter Mqtt topic filter.
 *
 * @param[in] topicFilterLength Length of the topic filter.
 *
 * @param[qos] qos Quality of Service
 *
 * @return  OtaMqttSuccess if success , other error code on failure.
 */
static OtaMqttStatus_t mqttUnsubscribe( const char * pTopicFilter,
                                        uint16_t topicFilterLength,
                                        uint8_t qos );

/**
 * @brief Handle HTTP response.
 *
 * @param[in] pResponse Pointer to http response buffer.
 * @return OtaHttpStatus_t OtaHttpSuccess if success or failure code otherwise.
 */
static OtaHttpStatus_t handleHttpResponse( const HTTPResponse_t * pResponse );

/**
 * @brief Initialize OTA Http interface.
 *
 * @param[in] pUrl Pointer to the pre-signed url for downloading update file.
 * @return OtaHttpStatus_t OtaHttpSuccess if success ,
 *                         OtaHttpInitFailed on failure.
 */
static OtaHttpStatus_t httpInit( char * pUrl );

/**
 * @brief Request file block over HTTP.
 *
 * @param[in] rangeStart  Starting index of the file data
 * @param[in] rangeEnd    Last index of the file data
 * @return OtaHttpStatus_t OtaHttpSuccess if success ,
 *                         other errors on failure.
 */
static OtaHttpStatus_t httpRequest( uint32_t rangeStart,
                                    uint32_t rangeEnd );

/**
 * @brief Deinitialize and cleanup of the HTTP connection.
 *
 * @return OtaHttpStatus_t  OtaHttpSuccess if success ,
 *                          OtaHttpRequestFailed on failure.
 */
static OtaHttpStatus_t httpDeinit( void );

/**
 * @brief Initialize MQTT by setting up transport interface and network.
 *
 * @param[in] pMqttContext Structure representing MQTT connection.
 * @param[in] pNetworkContext Network context to connect on.
 * @return int EXIT_SUCCESS if MQTT component is initialized
 */
static int initializeMqtt( MQTTContext_t * pMqttContext,
                           NetworkContext_t * pNetworkContext );

/**
 * @brief Attempt to connect to the MQTT broker.
 *
 * @return int EXIT_SUCCESS if a connection is established.
 */
static BaseType_t establishConnection( void );

/**
 * @brief Disconnect from the MQTT broker.
 *
 */
static void disconnect( void );

/**
 * @brief OTA agent task.
 *
 * @param[in] pParam Can be used to pass down functionality to the agent task
 */
static void otaTask( void * pParam );

/**
 * @brief Start OTA demo.
 *
 * @return   pPASS or pdFAIL.
 */
static BaseType_t startOTADemo( void );

/**
 * @brief Set OTA interfaces.
 *
 * @param[in]  pOtaInterfaces pointer to OTA interface structure.
 *
 * @return   None.
 */
static void setOtaInterfaces( OtaInterfaces_t * pOtaInterfaces );

/**
 * @brief Random number to be used as a back-off value for retrying connection.
 *
 * @return uint32_t The generated random number.
 */
static int32_t prvGenerateRandomNumber();

/* Callbacks used to handle different events. */

/**
 * @brief The OTA agent has completed the update job or it is in
 * self test mode. If it was accepted, we want to activate the new image.
 * This typically means we should reset the device to run the new firmware.
 * If now is not a good time to reset the device, it may be activated later
 * by your user code. If the update was rejected, just return without doing
 * anything and we'll wait for another job. If it reported that we should
 * start test mode, normally we would perform some kind of system checks to
 * make sure our new firmware does the basic things we think it should do
 * but we'll just go ahead and set the image as accepted for demo purposes.
 * The accept function varies depending on your platform. Refer to the OTA
 * PAL implementation for your platform in aws_ota_pal.c to see what it
 * does for you.
 *
 * @param[in] event Event from OTA lib of type OtaJobEvent_t.
 * @return None.
 */
static void otaAppCallback( OtaJobEvent_t event,
                            const void * pData );

/**
 * @brief Callback registered with the OTA library that notifies the OTA agent
 * of an incoming PUBLISH containing a job document.
 *
 * @param[in] pContext MQTT context which stores the connection.
 * @param[in] pPublishInfo MQTT packet information which stores details of the
 * job document.
 */
static void mqttJobCallback( MQTTContext_t * pContext,
                             MQTTPublishInfo_t * pPublishInfo );

/**
 * @brief Callback that notifies the OTA library when a data block is received.
 *
 * @param[in] pContext MQTT context which stores the connection.
 * @param[in] pPublishInfo MQTT packet that stores the information of the file block.
 */
static void mqttDataCallback( MQTTContext_t * pContext,
                              MQTTPublishInfo_t * pPublishInfo );

/**
 * @brief callback to use with the MQTT context to notify incoming packet events.
 *
 * @param[in] pMqttContext MQTT context which stores the connection.
 * @param[in] pPacketInfo Parameters of the incoming packet.
 * @param[in] pDeserializedInfo Deserialized packet information to be dispatched by
 * the subscription manager to event callbacks.
 */
static void mqttEventCallback( MQTTContext_t * pMqttContext,
                               MQTTPacketInfo_t * pPacketInfo,
                               MQTTDeserializedInfo_t * pDeserializedInfo );

/* Callbacks to register with the Subscription Manager. */
static SubscriptionManagerCallback_t otaMessageCallback[ OtaNumOfMessageType ] = { mqttJobCallback, mqttDataCallback };

/*-----------------------------------------------------------*/

void otaEventBufferFree( OtaEventData_t * const pxBuffer )
{
    if( xSemaphoreTake( xBufferSemaphore, portMAX_DELAY ) == pdTRUE )
    {
        pxBuffer->bufferUsed = false;
        ( void ) xSemaphoreGive( xBufferSemaphore );
    }
    else
    {
        LogError( ( "Failed to get buffer semaphore." ) );
    }
}

/*-----------------------------------------------------------*/

OtaEventData_t * otaEventBufferGet( void )
{
    uint32_t ulIndex = 0;
    OtaEventData_t * pFreeBuffer = NULL;

    if( xSemaphoreTake( xBufferSemaphore, portMAX_DELAY ) == pdTRUE )
    {
        for( ulIndex = 0; ulIndex < otaconfigMAX_NUM_OTA_DATA_BUFFERS; ulIndex++ )
        {
            if( eventBuffer[ ulIndex ].bufferUsed == false )
            {
                eventBuffer[ ulIndex ].bufferUsed = true;
                pFreeBuffer = &eventBuffer[ ulIndex ];
                break;
            }
        }

        ( void ) xSemaphoreGive( xBufferSemaphore );
    }
    else
    {
        LogError( ( "Failed to get buffer semaphore." ) );
    }

    return pFreeBuffer;
}

/*-----------------------------------------------------------*/

static void otaAppCallback( OtaJobEvent_t event,
                            const void * pData )
{
    OtaErr_t err = OtaErrUninitialized;

    switch( event )
    {
        case OtaJobEventActivate:
            LogInfo( ( "Received OtaJobEventActivate callback from OTA Agent." ) );

            /* Activate the new firmware image. */
            OTA_ActivateNewImage();

            /* Shutdown OTA Agent. */
            OTA_Shutdown( 0 );

            /* Requires manual activation of new image.*/
            LogError( ( "New image activation failed." ) );

            break;

        case OtaJobEventFail:
            LogInfo( ( "Received OtaJobEventFail callback from OTA Agent." ) );

            /* Nothing special to do. The OTA agent handles it. */
            break;

        case OtaJobEventStartTest:

            /* This demo just accepts the image since it was a good OTA update and networking
             * and services are all working (or we would not have made it this far). If this
             * were some custom device that wants to test other things before validating new
             * image, this would be the place to kick off those tests before calling
             * OTA_SetImageState() with the final result of either accepted or rejected. */

            LogInfo( ( "Received OtaJobEventStartTest callback from OTA Agent." ) );
            err = OTA_SetImageState( OtaImageStateAccepted );

            if( err != OtaErrNone )
            {
                LogError( ( " Failed to set image state as accepted." ) );
            }
            else
            {
                LogInfo( ( "Successfully updated with the new image." ) );
            }

            break;

        case OtaJobEventProcessed:
            LogDebug( ( "Received OtaJobEventProcessed callback from OTA Agent." ) );

            if( pData != NULL )
            {
                otaEventBufferFree( ( OtaEventData_t * ) pData );
            }

            break;

        case OtaJobEventSelfTestFailed:
            LogDebug( ( "Received OtaJobEventSelfTestFailed callback from OTA Agent." ) );

            /* Requires manual activation of previous image as self-test for
             * new image downloaded failed.*/
            LogError( ( "Self-test of new image failed, shutting down OTA Agent." ) );

            /* Shutdown OTA Agent. */
            OTA_Shutdown( 0 );


            break;

        default:
            LogDebug( ( "Received invalid callback event from OTA Agent." ) );
    }
}
/*-----------------------------------------------------------*/

static void mqttJobCallback( MQTTContext_t * pContext,
                             MQTTPublishInfo_t * pPublishInfo )
{
    OtaEventData_t * pData;
    OtaEventMsg_t eventMsg = { 0 };

    assert( pPublishInfo != NULL );
    assert( pContext != NULL );
    ( void ) pContext;

    LogInfo( ( "Received job message callback, size %ld.\n\n", pPublishInfo->payloadLength ) );

    pData = otaEventBufferGet();

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

static void mqttDataCallback( MQTTContext_t * pContext,
                              MQTTPublishInfo_t * pPublishInfo )
{
    OtaEventData_t * pData;
    OtaEventMsg_t eventMsg = { 0 };

    assert( pPublishInfo != NULL );
    assert( pContext != NULL );
    ( void ) pContext;

    LogInfo( ( "Received data message callback, size %zu.\n\n", pPublishInfo->payloadLength ) );

    pData = otaEventBufferGet();

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

static void mqttEventCallback( MQTTContext_t * pMqttContext,
                               MQTTPacketInfo_t * pPacketInfo,
                               MQTTDeserializedInfo_t * pDeserializedInfo )
{
    assert( pMqttContext != NULL );
    assert( pPacketInfo != NULL );
    assert( pDeserializedInfo != NULL );

    /* Handle incoming publish. The lower 4 bits of the publish packet
     * type is used for the dup, QoS, and retain flags. Hence masking
     * out the lower bits to check if the packet is publish. */
    if( ( pPacketInfo->type & 0xF0U ) == MQTT_PACKET_TYPE_PUBLISH )
    {
        assert( pDeserializedInfo->pPublishInfo != NULL );
        /* Handle incoming publish. */
        SubscriptionManager_DispatchHandler( pMqttContext, pDeserializedInfo->pPublishInfo );
    }
    else
    {
        /* Handle other packets. */
        switch( pPacketInfo->type )
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
                           pDeserializedInfo->packetIdentifier ) );
                break;

            /* Any other packet type is invalid. */
            default:
                LogError( ( "Unknown packet type received:(%02x).\n\n",
                            pPacketInfo->type ) );
        }
    }
}

/*-----------------------------------------------------------*/

static int32_t prvGenerateRandomNumber()
{
    uint32_t ulRandomNum;

    /* Set the return value as negative to indicate failure. */
    int32_t lOutput = -1;

    /* Use the PKCS11 module to generate a random number. */
    if( xPkcs11GenerateRandomNumber( ( uint8_t * ) &ulRandomNum,
                                     ( sizeof( ulRandomNum ) ) ) == pdPASS )
    {
        lOutput = ( int32_t ) ( ulRandomNum & INT32_MAX );
    }

    return lOutput;
}


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

/*-----------------------------------------------------------*/

static int initializeMqtt( MQTTContext_t * pMqttContext,
                           NetworkContext_t * pNetworkContext )
{
    int returnStatus = EXIT_SUCCESS;
    MQTTStatus_t mqttStatus = MQTTBadParameter;
    MQTTFixedBuffer_t networkBuffer;
    TransportInterface_t transport;

    assert( pMqttContext != NULL );
    assert( pNetworkContext != NULL );

    /* Fill in TransportInterface send and receive function pointers.
     * For this demo, TCP sockets are used to send and receive data
     * from network. Network context is TLS.*/
    transport.pNetworkContext = pNetworkContext;
    transport.send = SecureSocketsTransport_Send;
    transport.recv = SecureSocketsTransport_Recv;

    /* Fill the values for network buffer. */
    networkBuffer.pBuffer = otaNetworkBuffer;
    networkBuffer.size = OTA_NETWORK_BUFFER_SIZE;

    /* Initialize MQTT library. */
    mqttStatus = MQTT_Init( pMqttContext,
                            &transport,
                            prvGetTimeMs,
                            mqttEventCallback,
                            &networkBuffer );

    if( mqttStatus != MQTTSuccess )
    {
        returnStatus = EXIT_FAILURE;
        LogError( ( "MQTT init failed: Status = %s.", MQTT_Status_strerror( mqttStatus ) ) );
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/
static BaseType_t prvConnectToServerWithBackoffRetries( NetworkContext_t * pNetworkContext )
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
        xNetworkStatus = SecureSocketsTransport_Connect( pNetworkContext,
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

static BaseType_t establishMqttSession( MQTTContext_t * pxMqttContext )
{
    BaseType_t xStatus = pdPASS;
    MQTTStatus_t mqttStatus = MQTTBadParameter;
    MQTTConnectInfo_t connectInfo = { 0 };

    bool sessionPresent = false;


    /* Establish MQTT session by sending a CONNECT packet. */

    /* If #createCleanSession is true, start with a clean session
     * i.e. direct the MQTT broker to discard any previous session data.
     * If #createCleanSession is false, directs the broker to attempt to
     * reestablish a session which was already present. */
    connectInfo.cleanSession = true;

    /* The client identifier is used to uniquely identify this MQTT client to
     * the MQTT broker. In a production device the identifier can be something
     * unique, such as a device serial number. */
    connectInfo.pClientIdentifier = democonfigCLIENT_IDENTIFIER;
    connectInfo.clientIdentifierLength = ( uint16_t ) strlen( democonfigCLIENT_IDENTIFIER );

    /* The maximum time interval in seconds which is allowed to elapse
     * between two Control Packets.
     * It is the responsibility of the Client to ensure that the interval between
     * Control Packets being sent does not exceed the this Keep Alive value. In the
     * absence of sending any other Control Packets, the Client MUST send a
     * PINGREQ Packet. */
    connectInfo.keepAliveSeconds = MQTT_KEEP_ALIVE_INTERVAL_SECONDS;

    if( xSemaphoreTake( xMqttMutex, portMAX_DELAY ) == pdTRUE )
    {
        /* Send MQTT CONNECT packet to broker. */
        mqttStatus = MQTT_Connect( pxMqttContext, &connectInfo, NULL, CONNACK_RECV_TIMEOUT_MS, &sessionPresent );

        xSemaphoreGive( xMqttMutex );
    }
    else
    {
        LogError( ( "Failed to acquire mutex for executing MQTT_Connect"
                    ",errno=%s",
                    strerror( errno ) ) );
    }

    if( mqttStatus != MQTTSuccess )
    {
        xStatus = pdFAIL;
        LogError( ( "Connection with MQTT broker failed with status %s.",
                    MQTT_Status_strerror( mqttStatus ) ) );
    }
    else
    {
        LogInfo( ( "MQTT connection successfully established with broker.\n\n" ) );
    }

    return xStatus;
}

static BaseType_t establishConnection( void )
{
    BaseType_t xStatus = pdFAIL;

    /* Attempt to connect to the MQTT broker. If connection fails, retry after
     * a timeout. Timeout value will be exponentially increased till the maximum
     * attempts are reached or maximum timeout value is reached. The function
     * returns EXIT_FAILURE if the TCP connection cannot be established to
     * broker after configured number of attempts. */
    xStatus = prvConnectToServerWithBackoffRetries( &networkContextMqtt );

    if( xStatus != pdPASS )
    {
        /* Log error to indicate connection failure. */
        LogError( ( "Failed to connect to MQTT broker %s.",
                    democonfigMQTT_BROKER_ENDPOINT ) );
    }
    else
    {
        /* Sends an MQTT Connect packet over the already established TLS connection,
         * and waits for connection acknowledgment (CONNACK) packet. */
        LogInfo( ( "Creating an MQTT connection to %s.", democonfigMQTT_BROKER_ENDPOINT ) );
        xStatus = establishMqttSession( &mqttContext );

        if( xStatus != pdPASS )
        {
            LogError( ( "Failed creating an MQTT connection to %s.",
                        democonfigMQTT_BROKER_ENDPOINT ) );
        }
        else
        {
            LogDebug( ( "Success creating MQTT connection to %s.",
                        democonfigMQTT_BROKER_ENDPOINT ) );

            mqttSessionEstablished = true;
        }
    }

    return xStatus;
}

static void disconnect( void )
{
    /* Disconnect from broker. */
    LogInfo( ( "Disconnecting the MQTT connection with %s.", democonfigMQTT_BROKER_ENDPOINT ) );

    if( mqttSessionEstablished == true )
    {
        if( xSemaphoreTake( xMqttMutex, portMAX_DELAY ) == pdTRUE )
        {
            /* Disconnect MQTT session. */
            MQTT_Disconnect( &mqttContext );

            /* Clear the mqtt session flag. */
            mqttSessionEstablished = false;

            xSemaphoreGive( xMqttMutex );
        }
        else
        {
            LogError( ( "Failed to acquire mutex to execute MQTT_Disconnect"
                        ",errno=%s",
                        strerror( errno ) ) );
        }
    }
    else
    {
        LogError( ( "MQTT already disconnected." ) );
    }

    /* End TLS session, then close TCP connection. */
    ( void ) SecureSocketsTransport_Disconnect( &networkContextMqtt );
}

static int32_t connectToS3Server( NetworkContext_t * pNetworkContext,
                                  const char * pUrl )
{
    int32_t returnStatus = EXIT_SUCCESS;
    HTTPStatus_t httpStatus = HTTPSuccess;
    /* The location of the host address within the pre-signed URL. */
    const char * pAddress = NULL;
    TransportSocketStatus_t xNetworkStatus = TRANSPORT_SOCKET_STATUS_SUCCESS;
    SocketsConfig_t xSocketsConfig = { 0 };
    /* Information about the server to send the HTTP requests. */
    ServerInfo_t xServerInfo = { 0 };

    /* Configure credentials for TLS mutual authenticated session. */
    xSocketsConfig.enableTls = true;
    xSocketsConfig.pAlpnProtos = NULL;
    xSocketsConfig.maxFragmentLength = 0;
    xSocketsConfig.disableSni = false;
    xSocketsConfig.pRootCa = democonfigHTTPS_ROOT_CA_PEM;
    xSocketsConfig.rootCaSize = sizeof( democonfigHTTPS_ROOT_CA_PEM );
    xSocketsConfig.sendTimeoutMs = otaexampleTRANSPORT_SEND_RECV_TIMEOUT_MS;
    xSocketsConfig.recvTimeoutMs = otaexampleTRANSPORT_SEND_RECV_TIMEOUT_MS;

    /* Retrieve the address location and length from S3_PRESIGNED_GET_URL. */
    if( pUrl != NULL )
    {
        /* Retrieve the address location and length from S3_PRESIGNED_GET_URL. */
        httpStatus = getUrlAddress( pUrl,
                                    strlen( pUrl ),
                                    &pAddress,
                                    &serverHostLength );

        if( httpStatus != HTTPSuccess )
        {
            LogError( ( "URL %s parsing failed. Error code: %d",
                        pUrl,
                        httpStatus ) );
        }

        /* serverHost should consist only of the host address. */
        memcpy( serverHost, pAddress, serverHostLength );
        serverHost[ serverHostLength ] = '\0';
    }

    if( returnStatus != EXIT_FAILURE )
    {
        /* Initialize server information. */
        xServerInfo.pHostName = serverHost;
        xServerInfo.hostNameLength = serverHostLength;
        xServerInfo.port = democonfigHTTPS_PORT;

        /* Establish a TLS session with the HTTP server. This example connects
         * to the HTTP server as specified in SERVER_HOST and HTTPS_PORT in
         * demo_config.h. */
        LogInfo( ( "Establishing a TLS session with %s:%d.",
                   serverHost,
                   democonfigHTTPS_PORT ) );

        xNetworkStatus = SecureSocketsTransport_Connect( pNetworkContext,
                                                         &xServerInfo,
                                                         &xSocketsConfig );


        returnStatus = ( xNetworkStatus == TRANSPORT_SOCKET_STATUS_SUCCESS ) ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

static OtaHttpStatus_t handleHttpResponse( const HTTPResponse_t * pResponse )
{
    /* Return error code. */
    OtaHttpStatus_t ret = OtaHttpRequestFailed;

    OtaEventData_t * pData;
    OtaEventMsg_t eventMsg = { 0 };

    switch( pResponse->statusCode )
    {
        case HTTP_RESPONSE_PARTIAL_CONTENT:
            /* Get buffer to send event & data. */
            pData = otaEventBufferGet();

            if( pData != NULL )
            {
                /* Get the data from response buffer. */
                memcpy( pData->data, pResponse->pBody, pResponse->bodyLen );
                pData->dataLength = pResponse->bodyLen;

                /* Send job document received event. */
                eventMsg.eventId = OtaAgentEventReceivedFileBlock;
                eventMsg.pEventData = pData;
                OTA_SignalEvent( &eventMsg );

                ret = OtaHttpSuccess;
            }
            else
            {
                LogError( ( "Error: No OTA data buffers available." ) );

                ret = OtaHttpRequestFailed;
            }

            break;

        case HTTP_RESPONSE_BAD_REQUEST:
        case HTTP_RESPONSE_FORBIDDEN:
        case HTTP_RESPONSE_NOT_FOUND:
            /* Request the job document to get new url. */
            eventMsg.eventId = OtaAgentEventRequestJobDocument;
            eventMsg.pEventData = NULL;
            OTA_SignalEvent( &eventMsg );

            ret = OtaHttpSuccess;
            break;

        default:
            LogError( ( "Unhandled http response code: =%d.",
                        pResponse->statusCode ) );

            ret = OtaHttpRequestFailed;
    }

    return ret;
}

static OtaHttpStatus_t httpInit( char * pUrl )
{
    /* OTA lib return error code. */
    OtaHttpStatus_t ret = OtaHttpSuccess;

    /* HTTPS Client library return status. */
    HTTPStatus_t httpStatus = HTTPSuccess;

    /* Return value from libraries. */
    int32_t returnStatus = EXIT_SUCCESS;

    /* The length of the path within the pre-signed URL. This variable is
     * defined in order to store the length returned from parsing the URL, but
     * it is unused. The path used for the requests in this demo needs all the
     * query information following the location of the object, to the end of the
     * S3 presigned URL. */
    size_t pathLen = 0;


    /* Establish HTTPs connection */
    LogInfo( ( "Performing TLS handshake on top of the TCP connection." ) );

    /* Attempt to connect to the HTTPs server. If connection fails, retry after
     * a timeout. Timeout value will be exponentially increased till the maximum
     * attempts are reached or maximum timeout value is reached. The function
     * returns EXIT_FAILURE if the TCP connection cannot be established to
     * broker after configured number of attempts. */
    returnStatus = connectToS3Server( &networkContextHttp, pUrl );

    if( returnStatus == EXIT_SUCCESS )
    {
        /* Define the transport interface. */
        ( void ) memset( &transportInterfaceHttp, 0, sizeof( transportInterfaceHttp ) );
        transportInterfaceHttp.recv = SecureSocketsTransport_Recv;
        transportInterfaceHttp.send = SecureSocketsTransport_Send;
        transportInterfaceHttp.pNetworkContext = &networkContextHttp;

        /* Retrieve the path location from url. This
         * function returns the length of the path without the query into
         * pathLen, which is left unused in this demo. */
        httpStatus = getUrlPath( pUrl,
                                 strlen( pUrl ),
                                 &pPath,
                                 &pathLen );

        ret = ( httpStatus == HTTPSuccess ) ? OtaHttpSuccess : OtaHttpInitFailed;
    }
    else
    {
        /* Log an error to indicate connection failure after all
         * reconnect attempts are over. */
        LogError( ( "Failed to connect to HTTP server %s.",
                    serverHost ) );

        ret = OtaHttpInitFailed;
    }

    return ret;
}

static OtaHttpStatus_t httpRequest( uint32_t rangeStart,
                                    uint32_t rangeEnd )
{
    /* OTA lib return error code. */
    OtaHttpStatus_t ret = OtaHttpSuccess;

    /* Configurations of the initial request headers that are passed to
     * #HTTPClient_InitializeRequestHeaders. */
    HTTPRequestInfo_t requestInfo;
    /* Represents a response returned from an HTTP server. */
    HTTPResponse_t response;
    /* Represents header data that will be sent in an HTTP request. */
    HTTPRequestHeaders_t requestHeaders;

    /* Return value of all methods from the HTTP Client library API. */
    HTTPStatus_t httpStatus = HTTPSuccess;

    /* Reconnection required flag. */
    bool reconnectRequired = false;

    /* Initialize all HTTP Client library API structs to 0. */
    ( void ) memset( &requestInfo, 0, sizeof( requestInfo ) );
    ( void ) memset( &response, 0, sizeof( response ) );
    ( void ) memset( &requestHeaders, 0, sizeof( requestHeaders ) );

    /* Initialize the request object. */
    requestInfo.pHost = serverHost;
    requestInfo.hostLen = serverHostLength;
    requestInfo.pMethod = HTTP_METHOD_GET;
    requestInfo.methodLen = sizeof( HTTP_METHOD_GET ) - 1;
    requestInfo.pPath = pPath;
    requestInfo.pathLen = strlen( pPath );

    /* Set "Connection" HTTP header to "keep-alive" so that multiple requests
     * can be sent over the same established TCP connection. */
    requestInfo.reqFlags = HTTP_REQUEST_KEEP_ALIVE_FLAG;

    /* Set the buffer used for storing request headers. */
    requestHeaders.pBuffer = httpUserBuffer;
    requestHeaders.bufferLen = HTTP_USER_BUFFER_LENGTH;

    httpStatus = HTTPClient_InitializeRequestHeaders( &requestHeaders,
                                                      &requestInfo );

    HTTPClient_AddRangeHeader( &requestHeaders, rangeStart, rangeEnd );

    if( httpStatus == HTTPSuccess )
    {
        /* Initialize the response object. The same buffer used for storing
         * request headers is reused here. */
        response.pBuffer = httpUserBuffer;
        response.bufferLen = HTTP_USER_BUFFER_LENGTH;

        /* Send the request and receive the response. */
        httpStatus = HTTPClient_Send( &transportInterfaceHttp,
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
        if( ( httpStatus == HTTPNoResponse ) || ( httpStatus == HTTPNetworkError ) )
        {
            reconnectRequired = true;
        }
        else
        {
            LogError( ( "HTTPClient_Send failed: Error=%s.",
                        HTTPClient_strerror( httpStatus ) ) );

            ret = OtaHttpRequestFailed;
        }
    }
    else
    {
        /* Check if reconnection required. */
        if( response.respFlags & HTTP_RESPONSE_CONNECTION_CLOSE_FLAG )
        {
            reconnectRequired = true;
        }

        /* Handle the http response received. */
        ret = handleHttpResponse( &response );
    }

    if( reconnectRequired == true )
    {
        /* End TLS session, then close TCP connection. */
        ( void ) SecureSocketsTransport_Disconnect( &networkContextHttp );

        /* Try establishing connection to S3 server again. */
        if( connectToS3Server( &networkContextHttp, NULL ) == EXIT_SUCCESS )
        {
            ret = HTTPSuccess;
        }
        else
        {
            /* Log an error to indicate connection failure after all
             * reconnect attempts are over. */
            LogError( ( "Failed to connect to HTTP server %s.",
                        serverHost ) );

            ret = OtaHttpRequestFailed;
        }
    }

    return ret;
}

static OtaHttpStatus_t httpDeinit( void )
{
    OtaHttpStatus_t ret = OtaHttpSuccess;

    /* Nothing special to do here .*/

    return ret;
}

/*-----------------------------------------------------------*/

static OtaMessageType_t getOtaMessageType( const char * pTopicFilter,
                                           uint16_t topicFilterLength )
{
    int retStatus = EXIT_FAILURE;

    uint16_t stringIndex = 0U, fieldLength = 0U, i = 0U;
    OtaMessageType_t retMesageType = OtaNumOfMessageType;

    /* Lookup table for OTA message string. */
    static const char * const pOtaMessageStrings[ OtaNumOfMessageType ] =
    {
        OTA_TOPIC_JOBS,
        OTA_TOPIC_STREAM
    };

    /* Check topic prefix is valid.*/
    if( strncmp( pTopicFilter, OTA_TOPIC_PREFIX, ( size_t ) OTA_TOPIC_PREFIX_LENGTH ) == 0 )
    {
        stringIndex = OTA_TOPIC_PREFIX_LENGTH;

        retStatus = EXIT_SUCCESS;
    }

    /* Check if thing name is valid.*/
    if( retStatus == EXIT_SUCCESS )
    {
        retStatus = EXIT_FAILURE;

        /* Extract the thing name.*/
        for( ; stringIndex < topicFilterLength; stringIndex++ )
        {
            if( pTopicFilter[ stringIndex ] == ( char ) '/' )
            {
                break;
            }
            else
            {
                fieldLength++;
            }
        }

        if( fieldLength > 0 )
        {
            /* Check thing name.*/
            if( strncmp( &pTopicFilter[ stringIndex - fieldLength ],
                         democonfigCLIENT_IDENTIFIER,
                         ( size_t ) ( fieldLength ) ) == 0 )
            {
                stringIndex++;

                retStatus = EXIT_SUCCESS;
            }
        }
    }

    /* Check the message type from topic.*/
    if( retStatus == EXIT_SUCCESS )
    {
        fieldLength = 0;

        /* Extract the topic type.*/
        for( ; stringIndex < topicFilterLength; stringIndex++ )
        {
            if( pTopicFilter[ stringIndex ] == ( char ) '/' )
            {
                break;
            }
            else
            {
                fieldLength++;
            }
        }

        if( fieldLength > 0 )
        {
            for( i = 0; i < OtaNumOfMessageType; i++ )
            {
                /* check thing name.*/
                if( strncmp( &pTopicFilter[ stringIndex - fieldLength ],
                             pOtaMessageStrings[ i ],
                             ( size_t ) ( fieldLength ) ) == 0 )
                {
                    break;
                }
            }

            if( i < OtaNumOfMessageType )
            {
                retMesageType = i;
            }
        }
    }

    return retMesageType;
}

/*-----------------------------------------------------------*/



static OtaMqttStatus_t mqttSubscribe( const char * pTopicFilter,
                                      uint16_t topicFilterLength,
                                      uint8_t qos )
{
    OtaMqttStatus_t otaRet = OtaMqttSuccess;
    SubscriptionManagerStatus_t subscriptionStatus = SUBSCRIPTION_MANAGER_SUCCESS;
    OtaMessageType_t otaMessageType;

    MQTTStatus_t mqttStatus = MQTTBadParameter;
    MQTTContext_t * pMqttContext = &mqttContext;
    MQTTSubscribeInfo_t pSubscriptionList[ 1 ];

    assert( pTopicFilter != NULL );
    assert( topicFilterLength > 0 );

    /* Start with everything at 0. */
    ( void ) memset( ( void * ) pSubscriptionList, 0x00, sizeof( pSubscriptionList ) );

    /* Set the QoS , topic and topic length. */
    pSubscriptionList[ 0 ].qos = qos;
    pSubscriptionList[ 0 ].pTopicFilter = pTopicFilter;
    pSubscriptionList[ 0 ].topicFilterLength = topicFilterLength;

    if( xSemaphoreTake( xMqttMutex, portMAX_DELAY ) == pdTRUE )
    {
        /* Send SUBSCRIBE packet. */
        mqttStatus = MQTT_Subscribe( pMqttContext,
                                     pSubscriptionList,
                                     sizeof( pSubscriptionList ) / sizeof( MQTTSubscribeInfo_t ),
                                     MQTT_GetPacketId( pMqttContext ) );

        xSemaphoreGive( xMqttMutex );
    }
    else
    {
        LogError( ( "Failed to acquire mqtt mutex for executing MQTT_Subscribe"
                    ",errno=%s",
                    strerror( errno ) ) );
    }

    if( mqttStatus != MQTTSuccess )
    {
        LogError( ( "Failed to send SUBSCRIBE packet to broker with error = %u.",
                    mqttStatus ) );

        otaRet = OtaMqttSubscribeFailed;
    }
    else
    {
        LogInfo( ( "SUBSCRIBE topic %.*s to broker.\n\n",
                   topicFilterLength,
                   pTopicFilter ) );
    }

    otaMessageType = getOtaMessageType( pTopicFilter, topicFilterLength );

    assert( ( otaMessageType >= 0 ) && ( otaMessageType < OtaNumOfMessageType ) );

    /* Register callback to subscription manager. */
    subscriptionStatus = SubscriptionManager_RegisterCallback( pTopicFilter,
                                                               topicFilterLength,
                                                               otaMessageCallback[ otaMessageType ] );

    if( subscriptionStatus != SUBSCRIPTION_MANAGER_SUCCESS )
    {
        LogWarn( ( "Failed to register a callback to subscription manager with error = %d.",
                   subscriptionStatus ) );
    }

    return otaRet;
}

static OtaMqttStatus_t mqttPublish( const char * const pTopic,
                                    uint16_t topicLen,
                                    const char * pMsg,
                                    uint32_t msgSize,
                                    uint8_t qos )
{
    OtaMqttStatus_t otaRet = OtaMqttSuccess;

    MQTTStatus_t mqttStatus = MQTTBadParameter;
    MQTTPublishInfo_t publishInfo = { 0 };
    MQTTContext_t * pMqttContext = &mqttContext;

    /* Set the required publish parameters. */
    publishInfo.pTopicName = pTopic;
    publishInfo.topicNameLength = topicLen;
    publishInfo.qos = qos;
    publishInfo.pPayload = pMsg;
    publishInfo.payloadLength = msgSize;

    if( xSemaphoreTake( xMqttMutex, portMAX_DELAY ) == pdTRUE )
    {
        mqttStatus = MQTT_Publish( pMqttContext,
                                   &publishInfo,
                                   ( qos ) ? MQTT_GetPacketId( pMqttContext ) : 0U );

        xSemaphoreGive( xMqttMutex );
    }
    else
    {
        LogError( ( "Failed to acquire mqtt mutex for executing MQTT_Publish"
                    ",errno=%s",
                    strerror( errno ) ) );
    }

    if( mqttStatus != MQTTSuccess )
    {
        LogError( ( "Failed to send PUBLISH packet to broker with error = %u.", mqttStatus ) );

        otaRet = OtaMqttPublishFailed;
    }
    else
    {
        LogInfo( ( "Sent PUBLISH packet to broker %.*s to broker.\n\n",
                   topicLen,
                   pTopic ) );
    }

    return otaRet;
}

static OtaMqttStatus_t mqttUnsubscribe( const char * pTopicFilter,
                                        uint16_t topicFilterLength,
                                        uint8_t qos )
{
    OtaMqttStatus_t otaRet = OtaMqttSuccess;
    MQTTStatus_t mqttStatus = MQTTBadParameter;

    MQTTSubscribeInfo_t pSubscriptionList[ 1 ];
    MQTTContext_t * pMqttContext = &mqttContext;

    /* Start with everything at 0. */
    ( void ) memset( ( void * ) pSubscriptionList, 0x00, sizeof( pSubscriptionList ) );

    /* Set the QoS , topic and topic length. */
    pSubscriptionList[ 0 ].qos = qos;
    pSubscriptionList[ 0 ].pTopicFilter = pTopicFilter;
    pSubscriptionList[ 0 ].topicFilterLength = topicFilterLength;

    if( xSemaphoreTake( xMqttMutex, portMAX_DELAY ) == pdTRUE )
    {
        /* Send UNSUBSCRIBE packet. */
        mqttStatus = MQTT_Unsubscribe( pMqttContext,
                                       pSubscriptionList,
                                       sizeof( pSubscriptionList ) / sizeof( MQTTSubscribeInfo_t ),
                                       MQTT_GetPacketId( pMqttContext ) );

        xSemaphoreGive( xMqttMutex );
    }
    else
    {
        LogError( ( "Failed to acquire mutex for executing MQTT_Unsubscribe"
                    ",errno=%s",
                    strerror( errno ) ) );
    }

    if( mqttStatus != MQTTSuccess )
    {
        LogError( ( "Failed to send SUBSCRIBE packet to broker with error = %u.",
                    mqttStatus ) );

        otaRet = OtaMqttUnsubscribeFailed;
    }
    else
    {
        LogInfo( ( "SUBSCRIBE topic %.*s to broker.\n\n",
                   topicFilterLength,
                   pTopicFilter ) );
    }

    return otaRet;
}

/*-----------------------------------------------------------*/

static void setOtaInterfaces( OtaInterfaces_t * pOtaInterfaces )
{
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

    /* Initialize the OTA library HTTP Interface.*/
    pOtaInterfaces->http.init = httpInit;
    pOtaInterfaces->http.request = httpRequest;
    pOtaInterfaces->http.deinit = httpDeinit;

    /* Initialize the OTA library PAL Interface.*/
    pOtaInterfaces->pal.getPlatformImageState = otaPal_GetPlatformImageState;
    pOtaInterfaces->pal.setPlatformImageState = otaPal_SetPlatformImageState;
    pOtaInterfaces->pal.writeBlock = otaPal_WriteBlock;
    pOtaInterfaces->pal.activate = otaPal_ActivateNewImage;
    pOtaInterfaces->pal.closeFile = otaPal_CloseFile;
    pOtaInterfaces->pal.reset = otaPal_ResetDevice;
    pOtaInterfaces->pal.abort = otaPal_Abort;
    pOtaInterfaces->pal.createFile = otaPal_CreateFileForRx;
}

/*-----------------------------------------------------------*/

static void otaTask( void * pParam )
{
    /* Calling OTA agent task. */
    OTA_EventProcessingTask( pParam );
    LogInfo( ( "OTA Agent stopped." ) );
}

/*-----------------------------------------------------------*/
static BaseType_t startOTADemo( void )
{
    /* Status indicating a successful demo or not. */
    BaseType_t xStatus = pdPASS;

    /* coreMQTT library return status. */
    MQTTStatus_t mqttStatus = MQTTBadParameter;

    /* OTA library return status. */
    OtaErr_t otaRet = OtaErrNone;

    /* OTA Agent state returned from calling OTA_GetState.*/
    OtaState_t state = OtaAgentStateStopped;

    /* OTA event message used for sending event to OTA Agent.*/
    OtaEventMsg_t eventMsg = { 0 };

    /* OTA library packet statistics per job.*/
    OtaAgentStatistics_t otaStatistics = { 0 };

    /* OTA interface context required for library interface functions.*/
    OtaInterfaces_t otaInterfaces;

    /* Maximum time to wait for the OTA agent to get suspended. */
    int16_t suspendTimeout;

    /* Set OTA Library interfaces.*/
    setOtaInterfaces( &otaInterfaces );

    /****************************** Init OTA Library. ******************************/

    if( xStatus == pdPASS )
    {
        if( ( otaRet = OTA_Init( &otaBuffer,
                                 &otaInterfaces,
                                 ( const uint8_t * ) ( democonfigCLIENT_IDENTIFIER ),
                                 otaAppCallback ) ) != OtaErrNone )
        {
            LogError( ( "Failed to initialize OTA Agent, exiting = %u.",
                        otaRet ) );

            xStatus = pdFAIL;
        }
    }

    /****************************** Create OTA Task. ******************************/

    if( xStatus == pdPASS )
    {
        xStatus = xTaskCreate( otaTask,
                               "OTA Agent Task",
                               OTA_AGENT_TASK_STACK_SIZE,
                               NULL,
                               OTA_AGENT_TASK_PRIORITY,
                               NULL );

        if( xStatus != pdPASS )
        {
            LogError( ( "Failed to create OTA agent task:" ) );
        }
    }

    /****************************** OTA Demo loop. ******************************/

    if( xStatus == pdPASS )
    {
        /* Wait till OTA library is stopped, output statistics for currently running
         * OTA job */
        while( ( ( state = OTA_GetState() ) != OtaAgentStateStopped ) )
        {
            if( mqttSessionEstablished != true )
            {
                /* Connect to MQTT broker and create MQTT connection. */
                xStatus = establishConnection();

                if( xStatus == pdPASS )
                {
                    mqttSessionEstablished = true;

                    /* Check if OTA process was suspended and resume if required. */
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

            if( mqttSessionEstablished == true )
            {
                /* Acquire the mqtt mutex lock. */
                if( xSemaphoreTake( xMqttMutex, portMAX_DELAY ) == pdTRUE )
                {
                    /* Loop to receive packet from transport interface. */
                    mqttStatus = MQTT_ProcessLoop( &mqttContext, MQTT_PROCESS_LOOP_TIMEOUT_MS );
                    xSemaphoreGive( xMqttMutex );
                }
                else
                {
                    LogError( ( "Failed to acquire mutex to execute process loop" ) );
                }

                if( mqttStatus == MQTTSuccess )
                {
                    /* Get OTA statistics for currently executing job. */
                    OTA_GetStatistics( &otaStatistics );

                    LogInfo( ( " Received: %u   Queued: %u   Processed: %u   Dropped: %u",
                               otaStatistics.otaPacketsReceived,
                               otaStatistics.otaPacketsQueued,
                               otaStatistics.otaPacketsProcessed,
                               otaStatistics.otaPacketsDropped ) );

                    /* Delay if mqtt process loop is set to zero.*/
                    if( MQTT_PROCESS_LOOP_TIMEOUT_MS > 0 )
                    {
                        vTaskDelay( pdMS_TO_TICKS( MQTT_PROCESS_LOOP_INTERVAL_MS ) );
                    }
                }
                else
                {
                    LogError( ( "MQTT_ProcessLoop returned with status = %s.",
                                MQTT_Status_strerror( mqttStatus ) ) );

                    /* Disconnect from broker and close connection. */
                    disconnect();

                    /* Set connection flag to false. */
                    mqttSessionEstablished = false;

                    /* Suspend OTA operations. */
                    otaRet = OTA_Suspend();

                    if( otaRet != OtaErrNone )
                    {
                        LogError( ( "OTA failed to suspend. "
                                    "StatusCode=%d.", otaRet ) );
                    }
                    else
                    {
                        suspendTimeout = OTA_SUSPEND_TIMEOUT_MS;

                        while( ( ( state = OTA_GetState() ) != OtaAgentStateSuspended ) && ( suspendTimeout > 0 ) )
                        {
                            /* Wait for OTA Library state to suspend */
                            vTaskDelay( pdMS_TO_TICKS( OTA_EXAMPLE_TASK_DELAY_MS ) );
                            suspendTimeout -= OTA_EXAMPLE_TASK_DELAY_MS;
                        }
                    }
                }
            }
        }
    }

    /****************************** Wait for OTA Thread. ******************************/

    return xStatus;
}

/*-----------------------------------------------------------*/

/**
 * @brief Entry point of demo.
 *
 * This example initializes the OTA library to enable OTA updates via the
 * MQTT broker. It simply connects to the MQTT broker with the users
 * credentials and spins in an indefinite loop to allow MQTT messages to be
 * forwarded to the OTA agent for possible processing. The OTA agent does all
 * of the real work; checking to see if the message topic is one destined for
 * the OTA agent. If not, it is simply ignored.
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
 *
 */
int RunOtaCoreHttpDemo( bool awsIotMqttMode,
                        const char * pIdentifier,
                        void * pNetworkServerInfo,
                        void * pNetworkCredentialInfo,
                        const IotNetworkInterface_t * pNetworkInterface )
{
    ( void ) awsIotMqttMode;
    ( void ) pIdentifier;
    ( void ) pNetworkServerInfo;
    ( void ) pNetworkCredentialInfo;
    ( void ) pNetworkInterface;

    /* Return error status. */
    int returnStatus = EXIT_SUCCESS;

    /* Semaphore initialization flag. */
    bool xBufferSemInitialized = false;
    bool xMqttMutexInitialized = false;
    bool xMqttAckSemInitialized = false;

    /* Maximum time in milliseconds to wait before exiting demo . */
    int16_t waitTimeoutMs = OTA_DEMO_EXIT_TIMEOUT_MS;

    LogInfo( ( "OTA over HTTP demo, Application version %u.%u.%u",
               appFirmwareVersion.u.x.major,
               appFirmwareVersion.u.x.minor,
               appFirmwareVersion.u.x.build ) );

    /* Initialize semaphore for buffer operations. */
    xBufferSemaphore = xSemaphoreCreateMutex();

    if( xBufferSemaphore == NULL )
    {
        LogError( ( "Failed to initialize buffer semaphore." ) );

        returnStatus = EXIT_FAILURE;
    }
    else
    {
        xBufferSemInitialized = true;
    }

    /* Initialize mutex for coreMQTT APIs. */
    xMqttMutex = xSemaphoreCreateMutex();

    if( xMqttMutex == NULL )
    {
        LogError( ( "Failed to initialize mutex for mqtt apis" ) );

        returnStatus = EXIT_FAILURE;
    }
    else
    {
        xMqttMutexInitialized = true;
    }

    /* Initialize mutex for coreMQTT APIs. */
    xMqttAckSem = xSemaphoreCreateBinary();

    if( xMqttAckSem == NULL )
    {
        LogError( ( "Failed to initialize semaphore for MQTT acknowledgments." ) );
        returnStatus = EXIT_FAILURE;
    }
    else
    {
        xMqttAckSemInitialized = true;
    }

    if( returnStatus == EXIT_SUCCESS )
    {
        /* Initialize MQTT library. Initialization of the MQTT library needs to be
         * done only once in this demo. */
        returnStatus = initializeMqtt( &mqttContext, &networkContextMqtt );
    }

    if( returnStatus == EXIT_SUCCESS )
    {
        /* Start OTA demo. */
        if( startOTADemo() != pdPASS )
        {
            returnStatus = EXIT_FAILURE;
        }
    }

    /* Disconnect from broker and close connection. */
    disconnect();

    /* Disconnect from S3 and close connection. */
    ( void ) SecureSocketsTransport_Disconnect( &networkContextHttp );

    if( xBufferSemInitialized == true )
    {
        /* Cleanup semaphore created for buffer operations. */
        vSemaphoreDelete( xBufferSemaphore );
    }

    if( xMqttMutexInitialized == true )
    {
        /* Cleanup mutex created for MQTT operations. */
        vSemaphoreDelete( xMqttMutex );
    }

    if( xMqttAckSemInitialized == true )
    {
        vSemaphoreDelete( xMqttAckSem );
    }

    /* Wait and log message before exiting demo. */
    while( waitTimeoutMs > 0 )
    {
        vTaskDelay( pdMS_TO_TICKS( OTA_EXAMPLE_TASK_DELAY_MS ) );
        waitTimeoutMs -= OTA_EXAMPLE_TASK_DELAY_MS;

        LogError( ( "Exiting demo in %d sec", waitTimeoutMs / 1000 ) );
    }

    return returnStatus;
}
