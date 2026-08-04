idf_component_register(
    SRCS "dmesh_module_loader.c"
    INCLUDE_DIRS "include" "../../../../mod_hello/include" "../../../../mod_lora/include"
    REQUIRES esp_partition esp_mm spi_flash heap freertos log driver dmesh_nimble
)
