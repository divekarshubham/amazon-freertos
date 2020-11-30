afr_module( NAME ota INTERNAL )

# Include Json library's source and header path variables.
include("${CMAKE_CURRENT_LIST_DIR}/ota/otaFilePaths.cmake")

# Add cmake files of module to metadata.
afr_module_cmake_files(${AFR_CURRENT_MODULE}
    ${CMAKE_CURRENT_LIST_DIR}/ota/otaFilePaths.cmake
)

afr_module_sources(
    ${AFR_CURRENT_MODULE}
    PRIVATE
        ${OTA_SOURCES}
        ${OTA_OS_FREERTOS_SOURCES}
        ${OTA_MQTT_SOURCES}
        ${OTA_HTTP_SOURCES}
)

afr_module_include_dirs(
    ${AFR_CURRENT_MODULE}
    PUBLIC
        ${OTA_INCLUDE_PUBLIC_DIRS}
        ${OTA_INCLUDE_OS_FREERTOS_DIRS}
    PRIVATE
        ${OTA_INCLUDE_PRIVATE_DIRS}
)

# Dependency of module on logging stack.
afr_module_dependencies(
    ${AFR_CURRENT_MODULE}
    PUBLIC
        AFR::logging
)

################################################################

# ota_demo_dependencies module.
# Metadata module used for the OTA library in the FreeRTOS console.
# It represents a collection of module dependencies required
# by the OTA demos.
# This module enables the FreeRTOS console experience of enabling
# library dependencies when selecting the MQTT library, so that the
# coreMQTT demos can be downloaded.
afr_module(NAME ota_demo_dependencies )

afr_set_lib_metadata(ID "ota_demo_dependencies")
afr_set_lib_metadata(DESCRIPTION "placeholder for ota")
afr_set_lib_metadata(DISPLAY_NAME "OTA")
afr_set_lib_metadata(CATEGORY "placeholder")
afr_set_lib_metadata(VERSION "placeholder")
afr_set_lib_metadata(IS_VISIBLE "true")

# Add cmake files of module to metadata.
afr_module_cmake_files(${AFR_CURRENT_MODULE}
    ${CMAKE_CURRENT_LIST_DIR}/ota_demo_dependencies.cmake
)

afr_module_sources(
    ${AFR_CURRENT_MODULE}
    PRIVATE
        # Adding sources so that CMake can generate the
        # ota_demo_dependencies target; otherwise, it gives the
        # "Cannot determine link language for target" error.
        ${OTA_MQTT_SOURCES}
)
afr_module_include_dirs(
    ${AFR_CURRENT_MODULE}
    PUBLIC
        ${OTA_INCLUDE_PUBLIC_DIRS}
        ${OTA_INCLUDE_OS_FREERTOS_DIRS}
    PRIVATE
        ${OTA_INCLUDE_PRIVATE_DIRS}
)

# Add dependencies of the coreMQTT demos in this target
# to support metadata required for FreeRTOS console.
afr_module_dependencies(
    ${AFR_CURRENT_MODULE}
    PUBLIC
        AFR::ota
        AFR::core_mqtt_demo_dependencies
        AFR::core_http_demo_dependencies
        AFR::backoff_algorithm
        AFR::ota::mcu_port
)

# Add dependency on PKCS11 Helpers module, that is required
# by the Secure Sockets based coreMQTT demo, ONLY if the board
# supports the PKCS11 module.
if(TARGET AFR::pkcs11_implementation::mcu_port)
    afr_module_dependencies(
        ${AFR_CURRENT_MODULE}
        PUBLIC
            AFR::pkcs11_helpers
    )
endif()

# Add more dependencies for Secure Sockets based MQTT demo
# (at demos/coreMQTT folder) ONLY if the board supports
# the Secure Sockets library.
if(TARGET AFR::secure_sockets::mcu_port)
    afr_module_dependencies(
        ${AFR_CURRENT_MODULE}
        PUBLIC
            AFR::transport_interface_secure_sockets
            AFR::secure_sockets
    )
endif()
