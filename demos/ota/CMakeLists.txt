# OTA demo module.
afr_demo_module(ota)

afr_set_demo_metadata(ID "OTA_DEMO_CORE_MQTT")
afr_set_demo_metadata(DESCRIPTION "An example that demonstrates the use of the OTA library.")
afr_set_demo_metadata(DISPLAY_NAME "OTA over MQTT Demo")

afr_module_cmake_files(${AFR_CURRENT_MODULE} 
    ${CMAKE_CURRENT_LIST_DIR}/CMakeLists.txt
)

afr_module_sources(
    ${AFR_CURRENT_MODULE}
    INTERFACE
        "${CMAKE_CURRENT_LIST_DIR}/ota_demo_core_mqtt.c"
)

afr_module_include_dirs(
    ${AFR_CURRENT_MODULE}
    INTERFACE
        ${AFR_DEMOS_DIR}/ota
)

afr_module_dependencies(
    ${AFR_CURRENT_MODULE}
    INTERFACE
        AFR::core_mqtt
        AFR::core_json
        AFR::retry_utils
        AFR::mqtt_subscription_manager
        AFR::ota    
)

# Include required library's source and header path variables.
#include( ${CMAKE_SOURCE_DIR}/libraries/ota/otaFilePaths.cmake )
#include( ${CMAKE_SOURCE_DIR}/libraries/coreMQTT/mqttFilePaths.cmake )
#
## Demo target.
#add_executable(${DEMO_NAME})
#
## librt is required to use OTA OS POSIX port.
## find_library(LIB_RT rt REQUIRED)
#
#target_sources(
#    ${DEMO_NAME}
#    PRIVATE
#        "ota_demo_core_mqtt.c"
#        ${OTA_SOURCES}
#        ${OTA_OS_POSIX_SOURCES}
#        ${OTA_MQTT_SOURCES}
#        ${MQTT_SOURCES}
#        ${MQTT_SERIALIZER_SOURCES}
#)
#target_link_libraries(
#    ${DEMO_NAME}
#    PRIVATE
#        ${LIB_RT}
#        ota_pal
#        clock_posix
#        openssl_posix
#        retry_utils_posix
#        mqtt_subscription_manager
#)
#
#target_include_directories(
#    ${DEMO_NAME}
#    PUBLIC
#        "${CMAKE_CURRENT_LIST_DIR}"
#        "${LOGGING_INCLUDE_DIRS}"
#        ${OTA_INCLUDE_PUBLIC_DIRS}
#        ${OTA_INCLUDE_PRIVATE_DIRS}
#        ${OTA_INCLUDE_OS_POSIX_DIRS}
#        ${MQTT_INCLUDE_PUBLIC_DIRS}
#)

if(ROOT_CA_CERT_PATH)
    target_compile_definitions(
        ${DEMO_NAME} PRIVATE
            ROOT_CA_CERT_PATH="${ROOT_CA_CERT_PATH}"
    )
endif()
if(BROKER_ENDPOINT)
    target_compile_definitions(
        ${DEMO_NAME} PRIVATE
            BROKER_ENDPOINT="${BROKER_ENDPOINT}"
    )
endif()
if(CLIENT_IDENTIFIER)
    target_compile_definitions(
        ${DEMO_NAME} PRIVATE
            CLIENT_IDENTIFIER="${CLIENT_IDENTIFIER}"
    )
endif()
