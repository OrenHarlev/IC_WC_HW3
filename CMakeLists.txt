
cmake_minimum_required(VERSION 3.15)

project(IC_WC_HW3 C)

set(CMAKE_C_STANDARD 99)

add_executable(fw.h FWLogger.c FWLogger.h FWModule.c FWPacketMatcher.c FWPacketMatcher.h FWPacketParser.h FWPacketParser.c FWRuleManager.c FWRuleManager.h FWConnectionManager.c FWConnectionManager.h ProxyHelper.c ProxyHelper.h)