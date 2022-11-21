cmake_minimum_required(VERSION 3.22)
project(unsecured_password_manager CXX)

set(CMAKE_CXX_STANDARD 20)

add_executable(passwd_manager src/main.cpp)

include_directories(
	include/
)
