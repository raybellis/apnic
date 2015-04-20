# - Find evldns
# This module defines
# EVLDNS_INCLUDE_DIR, where to find evldns headers
# EVLDNS_LIB, evldns libraries
# EvlDns_FOUND, If false, do not try to use evldns

set(EvlDns_EXTRA_PREFIXES /usr/local /opt/local "$ENV{HOME}")
foreach(prefix ${EvlDns_EXTRA_PREFIXES})
  list(APPEND EvlDns_INCLUDE_PATHS "${prefix}/include")
  list(APPEND EvlDns_LIB_PATHS "${prefix}/lib")
endforeach()

find_path(EVLDNS_INCLUDE_DIR evldns.h PATHS ${EvlDns_INCLUDE_PATHS})
find_library(EVLDNS_LIB NAMES evldns_add_server_all PATHS ${EvlDns_LIB_PATHS})

if (EVLDNS_LIB AND EVLDNS_INCLUDE_DIR)
  set(EvlDns_FOUND TRUE)
  set(EVLDNS_LIB ${EVLDNS_LIB})
else ()
  set(EvlDns_FOUND FALSE)
endif ()

if (EvlDns_FOUND)
  if (NOT EvlDns_FIND_QUIETLY)
    message(STATUS "Found evldns: ${EVLDNS_LIB} ${EVLDNS_INCLUDE_DIR}")
  endif ()
else ()
  if (EvlDns_FIND_REQUIRED)
    message(FATAL_ERROR "Could NOT find evldns.")
  endif ()
  message(STATUS "evldns NOT found.")
endif ()

mark_as_advanced(
    EVLDNS_LIB
    EVLDNS_INCLUDE_DIR
  )
