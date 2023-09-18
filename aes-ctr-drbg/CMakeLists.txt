cmake_minimum_required(VERSION 3.12)
project(drbg LANGUAGES C)

set(SOURCES
  rng.h
  aes.h

  rng.c
  aes.c
)

add_library(${PROJECT_NAME})
target_sources(${PROJECT_NAME} PRIVATE ${SOURCES})
target_compile_definitions(${PROJECT_NAME} PRIVATE -DAES256=1)
target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
