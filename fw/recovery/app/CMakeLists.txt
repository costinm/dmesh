idf_component_register(
    SRCS "main.c" "../transport/dmesh_flash_tcp/dmesh_flash_tcp.c"
    INCLUDE_DIRS "." "../../boot"
    PRIV_INCLUDE_DIRS "../transport/dmesh_flash_tcp"
    PRIV_REQUIRES esp_wifi esp_event esp_netif nvs_flash esp_partition esp_driver_uart
                  spi_flash mbedtls esp_system esp_hw_support lwip)

target_compile_definitions(${COMPONENT_LIB} PRIVATE DMESH_FLASH_ROLE_RECOVERY=1)
