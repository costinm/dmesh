idf_component_register(
    SRCS "dmesh_hw.c"
    INCLUDE_DIRS "include"
  REQUIRES esp_driver_rmt esp_driver_gpio
)
