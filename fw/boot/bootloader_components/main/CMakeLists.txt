idf_component_register(
    SRCS "bootloader_start.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES bootloader_support nvs_flash efuse)

if(NOT DEFINED ENV{DMESH_STAGE2_VERSION} OR "$ENV{DMESH_STAGE2_VERSION}" STREQUAL "")
    string(TIMESTAMP DMESH_STAGE2_DATE "%Y%m%d" UTC)
    set(DMESH_STAGE2_VERSION "${DMESH_STAGE2_DATE}000")
else()
    set(DMESH_STAGE2_VERSION "$ENV{DMESH_STAGE2_VERSION}")
endif()
if(NOT DMESH_STAGE2_VERSION MATCHES "^[0-9]+$")
    message(FATAL_ERROR "DMESH_STAGE2_VERSION must be numeric, got '${DMESH_STAGE2_VERSION}'")
endif()
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    DMESH_STAGE2_VERSION=${DMESH_STAGE2_VERSION})
