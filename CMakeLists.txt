cmake_minimum_required(VERSION 3.0)
project(apnic-master)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")

find_package(LibEvent REQUIRED)
include_directories(${LIBEVENT_INCLUDE_DIR})
set(LIBS ${LIBS} ${LIBEVENT_LIB})

find_package(EvlDns REQUIRED)
include_directories(${EVLDNS_INCLUDE_DIR})
set(LIBS ${LIBS} ${EVLDNS_LIB})

find_package(LDns REQUIRED)
set(LIBS ${LIBS} ${LDNS_LIBRARIES})

add_executable(apnic-master apnic.cc)
target_link_libraries(apnic-master ${LIBS})

