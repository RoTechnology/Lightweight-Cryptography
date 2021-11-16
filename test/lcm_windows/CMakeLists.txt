cmake_minimum_required(VERSION 3.17)
project(Test C)

set(CMAKE_C_STANDARD 99)

add_executable(Test main.c Taks.h aes.h)