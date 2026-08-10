idf_component_register(
    SRCS "dmesh_module_loader.c" "dmesh_hw_host.c"
    INCLUDE_DIRS "include" "../../../../mod_hello/include" "../../../../mod_lora/include" "../../../../mod_flash/include" "../../../../modules/include"
    REQUIRES esp_partition esp_mm esp_netif lwip spi_flash heap freertos log driver esp_adc dmesh_nimble
)
