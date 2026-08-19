cmake_minimum_required(VERSION 3.16)
project(tcpreplay_windows VERSION 4.6.0 LANGUAGES CXX)

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
