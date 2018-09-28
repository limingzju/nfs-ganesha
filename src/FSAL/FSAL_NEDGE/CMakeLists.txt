add_definitions(
  -D__USE_GNU
  -D_GNU_SOURCE
)

#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -I${NEDGE_HOME}/include/ccow")
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -L${NEDGE_HOME}/lib/")

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
