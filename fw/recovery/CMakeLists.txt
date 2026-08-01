cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
idf_build_set_property(MINIMAL_BUILD ON)
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/app")
project(dmesh-recovery)
