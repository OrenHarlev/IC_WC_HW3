
cmake_minimum_required(VERSION 3.15)

project(IC_WC_HW3 C)

set(CMAKE_C_STANDARD 99)

add_executable(fw.h FWLoger.c FWLoger.h FWModule.c FWNetworkFilter.c FWNetworkFilter.h FWPacketParser.h FWPacketParser.c FWRuleManager.c FWRuleManager.h)