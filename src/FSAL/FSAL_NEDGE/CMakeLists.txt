add_definitions(
  -D__USE_GNU
  -D_GNU_SOURCE
)

#IF(NEDGE_PREFIX)
#  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${NEDGE_PREFIX}/include -I/opt/nedge/src/ccow/include")
#  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -L${NEDGE_PREFIX}/lib -L/opt/nedge/lib -L/opt/nedge/src/ccow/src/libccow/.libs/ -lccow")
#ENDIF()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -I/opt/nedge/src/ccow/include")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I/opt/nedge/src/ccow/src/include")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -L/opt/nedge/lib/")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -L/opt/nedge/src/ccow/src/libccow/.libs/")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -L/opt/nedge/src/ccow/src/libccowfsio/.libs/")

set( LIB_PREFIX 64)

########### next target ###############

SET(fsalnedge_LIB_SRCS
   export.c
   file.c
   fsal_internal.c
   fsal_internal.h
   handle.c
   main.c
   nedge_methods.h
   fsal_up.c
)

add_library(fsalnedge SHARED ${fsalnedge_LIB_SRCS})

target_link_libraries(fsalnedge
#  zfswrap
  ccow
  ccowfsio
  ${SYSTEM_LIBRARIES}
)

set_target_properties(fsalnedge PROPERTIES VERSION 4.2.0 SOVERSION 4)

########### install files ###############

install(TARGETS fsalnedge COMPONENT fsal DESTINATION ${FSAL_DESTINATION} )
