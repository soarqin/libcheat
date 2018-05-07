cmake_minimum_required(VERSION 2.8.11)

project(libcheat)

OPTION(ENABLE_TEST "Enable test program" OFF)

add_library(cheat STATIC
    libcheat.c libcheat.h
)

if (ENABLE_TEST)
add_executable(test test.c)
target_link_libraries(test cheat)
endif()
