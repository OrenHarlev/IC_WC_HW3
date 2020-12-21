
cmake_minimum_required(VERSION 3.15)

project(IC_WC_HW3 C)

set(CMAKE_C_STANDARD 99)

add_executable(module/fw.h module/FWLogger.c module/FWLogger.h module/FWModule.c module/FWPacketMatcher.c module/FWPacketMatcher.h module/FWPacketParser.h module/FWPacketParser.c module/FWRuleManager.c module/FWRuleManager.h module/FWConnectionManager.c module/FWConnectionManager.h module/FWProxyHelper.c module/FWProxyHelper.h)