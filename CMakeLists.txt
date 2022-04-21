# CMakeLists files in this project can
# refer to the root source directory of the project as ${HELLO_SOURCE_DIR} and
# to the root binary directory of the project as ${HELLO_BINARY_DIR}.
cmake_minimum_required (VERSION 3.15.0)
project (bootimg)

if (MSVC)
    # warning level 4 and all warnings as errors
    add_compile_options(/W4 /WX)
else()
    # lots of warnings and all warnings as errors
    add_compile_options(-Wall -Wpedantic -Wextra -std=gnu99 -Os -s -DNO_MTK_SUPPORT=1
			-DROCKCHIP_SUPPORT=1)
endif()

add_subdirectory (mincrypt)
add_executable(bootimg libbootimg.c bootimg.c)
add_executable(imageinfo libbootimg.c main.c)
target_link_libraries (imageinfo LINK_PUBLIC mincrypt)
target_link_libraries (bootimg LINK_PUBLIC mincrypt)
