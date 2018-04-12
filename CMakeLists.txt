project(one-dedup)
cmake_minimum_required(VERSION 3.5)
add_subdirectory(src tools)


set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
include_directories(${PROJECT_SOURCE_DIR}/include)

# main
add_executable(dedup main.c)
#TARGET_LINK_LIBRARIES(dedup buse crypto ssl pthread zlog bplustree rabin)
TARGET_LINK_LIBRARIES(dedup buse_single crypto ssl pthread zlog bplustree rabin)