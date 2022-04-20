cmake_minimum_required(VERSION 3.21)
project(webserv)

set(CMAKE_CXX_STANDARD 98)

add_executable(webserv main.cpp options.hpp HTTPHeaderField.hpp HeaderFieldInfo.cpp HeaderFieldInfo.hpp)
