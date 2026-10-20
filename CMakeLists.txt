cmake_minimum_required(VERSION 3.16)
project(tcpreplay_windows VERSION 4.6.0 LANGUAGES CXX)

include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(tcpreplay_common STATIC
    packet_edit.cpp
    pcap_source.cpp
    rewrite_cli.cpp
    tcpprep_cache.cpp
)
target_include_directories(tcpreplay_common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_directories(tcpreplay_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/lib/x64)
target_link_libraries(tcpreplay_common PUBLIC wpcap Packet ws2_32)

# Public C ABI. The static archive has a distinct name because the shared
# library import archive is named libtcpreplay.lib on Windows.
add_library(libtcpreplay_static STATIC tcpreplay_api.cpp)
target_compile_definitions(libtcpreplay_static PUBLIC TCPREPLAY_STATIC)
set_target_properties(libtcpreplay_static PROPERTIES OUTPUT_NAME libtcpreplay_static)

add_library(libtcpreplay SHARED tcpreplay_api.cpp)
set_target_properties(libtcpreplay PROPERTIES OUTPUT_NAME libtcpreplay)

foreach(target libtcpreplay_static libtcpreplay)
    target_include_directories(${target} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    )
    target_link_directories(${target} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/lib/x64)
    target_link_libraries(${target} PUBLIC wpcap Packet ws2_32)
    set_target_properties(${target} PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
        ARCHIVE_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/lib/Debug
        ARCHIVE_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/lib/Release
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
        RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin/Debug
        RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin/Release
    )
endforeach()

add_executable(tcpreplay main.cpp)
target_link_libraries(tcpreplay PRIVATE tcpreplay_common)

add_executable(tcpreplay-edit main.cpp)
target_link_libraries(tcpreplay-edit PRIVATE tcpreplay_common)

add_executable(tcprewrite tcprewrite.cpp)
target_link_libraries(tcprewrite PRIVATE tcpreplay_common)

foreach(target tcpreplay tcpreplay-edit tcprewrite)
    set_target_properties(${target} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
        RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin/Debug
        RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin/Release
    )
endforeach()

option(TCPREPLAY_BUILD_EXAMPLES "Build libtcpreplay examples" ON)
if(TCPREPLAY_BUILD_EXAMPLES)
    add_executable(libtcpreplay_cpp_example examples/libtcpreplay.cpp)
    target_link_libraries(libtcpreplay_cpp_example PRIVATE libtcpreplay_static)
    set_target_properties(libtcpreplay_cpp_example PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
        RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin/Debug
        RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin/Release
    )
    install(TARGETS libtcpreplay_cpp_example RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

install(TARGETS tcpreplay tcpreplay-edit tcprewrite libtcpreplay libtcpreplay_static
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(FILES include/tcpreplay/tcpreplay_api.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tcpreplay
)
install(FILES lib/x64/wpcap.lib lib/x64/Packet.lib DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES examples/libtcpreplay.py DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES examples/libtcpreplay.cpp docs/LIBTCPREPLAY.md
    DESTINATION ${CMAKE_INSTALL_DATADIR}/tcpreplay
)
