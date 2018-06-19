project(one-dedup)
cmake_minimum_required(VERSION 3.5)


set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
include_directories(${PROJECT_SOURCE_DIR}/include)

set(D_FILE_OFFSET_BITS 64)

add_subdirectory(src)