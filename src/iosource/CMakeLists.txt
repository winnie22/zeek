
include(ZeekSubdir)

include_directories(BEFORE
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR}
)

add_subdirectory(pcap)

set(iosource_SRCS
    BPF_Program.cc
    Component.cc
    ManagerBase.cc
    Packet.cc
    PktDumper.cc
    PktSrc.cc
    )

if ( HAVE_EPOLL_H )
  set(iosource_SRCS ${iosource_SRCS} ManagerEpoll.cc)
elseif ( HAVE_KQUEUE )
  set(iosource_SRCS ${iosource_SRCS} ManagerKqueue.cc)
else ()
  set(iosource_SRCS ${iosource_SRCS} ManagerPoll.cc)
endif ()

bro_add_subdir_library(iosource ${iosource_SRCS})
add_dependencies(bro_iosource generate_outputs)
