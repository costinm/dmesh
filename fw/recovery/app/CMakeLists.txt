idf_component_register(
    SRCS "main.c" "../transport/dmesh_flash_tcp/dmesh_flash_tcp.c"
    INCLUDE_DIRS "."
    PRIV_INCLUDE_DIRS "../transport/dmesh_flash_tcp"
    PRIV_REQUIRES esp_wifi esp_event esp_netif nvs_flash esp_partition esp_driver_uart
                  spi_flash mbedtls esp_system esp_timer esp_hw_support lwip esp_driver_usb_serial_jtag)

# Set DMESH_FLASH_DEV_MODE=1 in the build environment only for development
# images. It makes signature failures non-fatal and skips received-block and
# final-image verification while exercising the transport.
if(NOT DEFINED ENV{DMESH_FLASH_DEV_MODE})
    set(DMESH_FLASH_DEV_MODE 0)
else()
    set(DMESH_FLASH_DEV_MODE $ENV{DMESH_FLASH_DEV_MODE})
endif()
target_compile_definitions(${COMPONENT_LIB} PRIVATE DMESH_FLASH_DEV_MODE=${DMESH_FLASH_DEV_MODE})
target_compile_definitions(${COMPONENT_LIB} PRIVATE DMESH_FLASH_ROLE_RECOVERY=1)
