cmake_minimum_required(VERSION 3.16)
project(ISAa)

set(CMAKE_CXX_STANDARD 20)

find_package(OpenSSL REQUIRED)

add_executable(ISAa main.cpp Sender.h Encryption.h Receiver.h icmp.h)
target_link_libraries(ISAa OpenSSL::SSL)
