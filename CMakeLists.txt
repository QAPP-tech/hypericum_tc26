CMAKE_MINIMUM_REQUIRED(VERSION 3.0.2)

PROJECT(hypericum)

SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
    "${CMAKE_SOURCE_DIR}/cmake/sanitizers-cmake/")

FIND_PACKAGE(Sanitizers)

SET(API_HEADER_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
SET(PARAMSETS_DIR  ${CMAKE_CURRENT_SOURCE_DIR}/include/paramsets)
SET(STREEBOG_DIR   ${CMAKE_CURRENT_SOURCE_DIR}/streebog)

SET(PARAMSET "fast_ver" CACHE STRING "Select a hypericum parameter set")
SET_PROPERTY(CACHE PARAMSET PROPERTY STRINGS "fast_ver"
                                             "fast_sign"
                                             "small_sign")
IF(NOT PARAMSET)
  SET(PARAMSET "fast_ver")
ENDIF()


MESSAGE(STATUS "Using Hypericum parameter set ${PARAMSET}")

SET(GOST_OPTIMIZATION CACHE STRING "Set GOST optimization level")
SET_PROPERTY(CACHE GOST_OPTIMIZATION PROPERTY STRINGS "0" "1" "2" "3")
IF(NOT GOST_OPTIMIZATION)
   SET(GOST_OPTIMIZATION "0")
ENDIF()

CONFIGURE_FILE(current-paramset.h.in current-paramset.h)

ADD_SUBDIRECTORY(${STREEBOG_DIR})

SET(HEADER_FILES ${API_HEADER_DIR}/api.h
                 ${API_HEADER_DIR}/params.h

                 ${PARAMSETS_DIR}/params_fast_ver.h
                 ${PARAMSETS_DIR}/params_fast_sign.h
                 ${PARAMSETS_DIR}/params_small_sign.h

                 sei.h
                 sei_cryptoapi.h
                 sei_urandom.h
                 drbg.h

                 stack.h
                 sign.h
                 adrs.h
                 pack.h
                 wotsc.h
                 hash.h
                 streebog.h
                 utils.h
                 xmss.h
                 xmssmt.h
                 fors.h)

SET(SOURCE_FILES
                 sei.c
                 sei_cryptoapi.c
                 sei_urandom.c
                 drbg.c

                 adrs.c
                 wotsc.c
                 sign.c
                 hash.c
                 utils.c
                 pack.c
                 stack.c
                 streebog.c
                 xmss.c
                 xmssmt.c
                 fors.c
                 hypericum.c)

ADD_LIBRARY(${PROJECT_NAME}
            ${HEADER_FILES}
            ${SOURCE_FILES})

TARGET_LINK_LIBRARIES(${PROJECT_NAME} PUBLIC streebog)
ADD_SANITIZERS(${PROJECT_NAME})
TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PRIVATE ${STREEBOG_DIR})
TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC ${API_HEADER_DIR}
                                                  ${CMAKE_CURRENT_BINARY_DIR})

TARGET_COMPILE_FEATURES(${PROJECT_NAME} PRIVATE c_std_99)

ADD_EXECUTABLE(PQCgenKAT_sign PQCgenKAT_sign.c)
TARGET_LINK_LIBRARIES(PQCgenKAT_sign PRIVATE ${PROJECT_NAME})
ADD_SANITIZERS(PQCgenKAT_sign)

ADD_EXECUTABLE(hypericum_example example.c)
TARGET_LINK_LIBRARIES(hypericum_example PRIVATE ${PROJECT_NAME})
ADD_SANITIZERS(hypericum_example)
