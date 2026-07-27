idf_component_register(
    SRCS "dmesh_nimble.c"
    INCLUDE_DIRS "include" "../dmesh_hw/include"
    REQUIRES bt nvs_flash dmesh_hw
)
