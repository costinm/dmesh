idf_component_register(
    SRCS "dmesh_module_loader.c" "dmesh_hw_host.c" "dmesh_module_weak_platform.c"
    INCLUDE_DIRS "include" "../../../mod_hello/include" "../../../mod_lora/include" "../../include"
    REQUIRES esp_partition esp_mm esp_netif lwip spi_flash heap freertos log driver esp_adc
             esp_timer esp_driver_gpio esp_driver_spi
)
