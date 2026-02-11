# This file is part of Media Storage, storing files onto YouTube
# Copyright (C) Brandon Li <https://brandonli.me/>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

cmake_minimum_required(VERSION 3.22)
project(media_storage LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
find_package(OpenMP REQUIRED)
find_package(Qt6 REQUIRED COMPONENTS Core Widgets)

# Enable Qt MOC, UIC, and RCC for GUI only
set(CMAKE_AUTOMOC OFF)
set(CMAKE_AUTOUIC OFF)
set(CMAKE_AUTORCC OFF)

pkg_check_modules(AVCODEC REQUIRED IMPORTED_TARGET libavcodec)
pkg_check_modules(AVFORMAT REQUIRED IMPORTED_TARGET libavformat)
pkg_check_modules(AVUTIL REQUIRED IMPORTED_TARGET libavutil)
pkg_check_modules(SWSCALE REQUIRED IMPORTED_TARGET libswscale)
pkg_check_modules(SWRESAMPLE REQUIRED IMPORTED_TARGET libswresample)

add_executable(media_storage)
add_executable(media_storage_gui)

add_subdirectory(src)

target_link_libraries(media_storage PRIVATE
        PkgConfig::AVCODEC
        PkgConfig::AVFORMAT
        PkgConfig::AVUTIL
        PkgConfig::SWSCALE
        PkgConfig::SWRESAMPLE
        OpenMP::OpenMP_CXX
)

target_link_libraries(media_storage_gui PRIVATE
        PkgConfig::AVCODEC
        PkgConfig::AVFORMAT
        PkgConfig::AVUTIL
        PkgConfig::SWSCALE
        PkgConfig::SWRESAMPLE
        OpenMP::OpenMP_CXX
        Qt6::Core
        Qt6::Widgets
)

# Enable Qt MOC only for GUI target
set_target_properties(media_storage_gui PROPERTIES AUTOMOC ON AUTOUIC ON)

# Check for OpenMP
if (MSVC)
    target_compile_options(media_storage PRIVATE
            $<$<CONFIG:Release>:/O2>
            /arch:AVX2
    )
    target_compile_options(media_storage_gui PRIVATE
            $<$<CONFIG:Release>:/O2>
            /arch:AVX2
    )
else ()
    target_compile_options(media_storage PRIVATE -march=native)
    if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|i386")
        target_compile_options(media_storage_gui PRIVATE -O2 -mssse3)
    else ()
        target_compile_options(media_storage_gui PRIVATE -O2 -march=native)
    endif ()
endif ()
