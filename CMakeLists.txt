# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

set(ZEPHYR_EXTRA_MODULES "${CMAKE_SOURCE_DIR}/modules/say_hello")

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(multiTag)

target_sources(app PRIVATE src/main.c)
