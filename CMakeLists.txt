cmake_minimum_required(VERSION 3.17)
project(anti_shadowsocksR)

set(CMAKE_CXX_STANDARD 14)

add_executable(anti_shadowsocksR main.cpp)

target_link_libraries(anti_shadowsocksR pcap)

target_link_libraries(anti_shadowsocksR crypto)

target_link_libraries(anti_shadowsocksR z)

target_link_libraries(anti_shadowsocksR sodium)



