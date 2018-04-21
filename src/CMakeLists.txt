include_directories(${PROJECT_SOURCE_DIR}/include)

LINK_DIRECTORIES(${PROJECT_BINARY_DIR}/lib)
include_directories(../include)

set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)

# BUSE
#ADD_LIBRARY(buse STATIC buse.c threadpool.c)
# BUSE_single
add_library(buse_single buse_single.c)

# b+tree
ADD_LIBRARY(bplustree STATIC bplustree.c)

# rabin algorithm
add_library(rabin STATIC rabin.c)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# b+tree test
add_executable(bplustree_test bplustree_test.c)
target_link_libraries(bplustree_test bplustree)

# rabin test
add_executable(rabin_test rabin_test.c)
target_link_libraries(rabin_test rabin crypto ssl)

# read hash file
add_executable(read_hashfile read_hashfile.c libhashfile.c)




