idf_component_register(
    SRCS "bootloader_start.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES bootloader_support nvs_flash efuse)
