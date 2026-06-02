cmake_minimum_required(VERSION 3.16)

project(NetworkLab LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/Bin)

find_package(Threads REQUIRED)
find_package(CURL REQUIRED)

set(NETWORK_COMMON_SOURCES
    Source/Utils.cpp
    Source/Packet.cpp
)

set(NETWORK_DHCP_SOURCES
    ${NETWORK_COMMON_SOURCES}
    Source/DHCP_Starvation.cpp
)

function(add_network_tool target source)
    add_executable(${target} ${source} ${ARGN})
    target_include_directories(${target} PRIVATE Include)
    target_link_libraries(${target} PRIVATE Threads::Threads)
endfunction()

add_network_tool(arp_scan arp_scan.cpp ${NETWORK_COMMON_SOURCES})
add_network_tool(arp_spoofing arp_spoofing.cpp ${NETWORK_COMMON_SOURCES})
add_network_tool(dns_monitor dns_monitor.cpp ${NETWORK_COMMON_SOURCES})
add_network_tool(dns_scan dns_scan.cpp ${NETWORK_COMMON_SOURCES})
add_network_tool(icmp6_scan icmp6_scan.cpp ${NETWORK_COMMON_SOURCES})
add_network_tool(ndp_spoofing ndp_spoofing.cpp ${NETWORK_COMMON_SOURCES})
add_network_tool(dhcp dhcp.cpp ${NETWORK_DHCP_SOURCES})
add_network_tool(release_fclients release_fclients.cpp ${NETWORK_DHCP_SOURCES})
add_network_tool(release_aclients release_aclients.cpp ${NETWORK_DHCP_SOURCES})
add_network_tool(dhcp_server dhcp_server.cpp ${NETWORK_COMMON_SOURCES})
add_network_tool(dhcpv6 dhcpv6.cpp ${NETWORK_COMMON_SOURCES})
add_network_tool(dns_rr dns_rr.cpp ${NETWORK_COMMON_SOURCES})
add_network_tool(netlink netlink.cpp ${NETWORK_COMMON_SOURCES})

target_link_libraries(arp_scan PRIVATE CURL::libcurl)
target_link_libraries(icmp6_scan PRIVATE CURL::libcurl)

add_custom_target(prepare_runtime_dirs ALL
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/Clients
)
