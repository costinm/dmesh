idf_component_register(
    SRCS "dmesh_boot_health.c" "boot_health_flash.c"
    INCLUDE_DIRS "." "../../../../boot"
    REQUIRES spi_flash
)
