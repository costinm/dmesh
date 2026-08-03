set(DMESH_RECOVERY_TRANSPORT_DIR
    "$ENV{DMESH_RECOVERY_TRANSPORT_DIR}"
    CACHE PATH "Directory containing the Recovery-owned flash transport")
if(NOT DMESH_RECOVERY_TRANSPORT_DIR)
    set(DMESH_RECOVERY_TRANSPORT_DIR
        "${CMAKE_CURRENT_LIST_DIR}/../../../../recovery/transport/dmesh_flash_tcp")
endif()

set(DMESH_FLASH_TCP_DIR "${DMESH_RECOVERY_TRANSPORT_DIR}")

# The implementation is owned by Recovery. Main imports this platform-only
# transport so the Recovery repository boundary does not depend on the mesh
# application.
idf_component_register(
    SRCS "${DMESH_FLASH_TCP_DIR}/dmesh_flash_tcp.c"
    INCLUDE_DIRS "${DMESH_FLASH_TCP_DIR}"
    REQUIRES esp_partition spi_flash esp_wifi lwip nvs_flash mbedtls esp_system esp_hw_support
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE DMESH_FLASH_ROLE_MAIN=1)
