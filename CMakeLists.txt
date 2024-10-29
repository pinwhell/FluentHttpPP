cmake_minimum_required(VERSION 3.15)

project(FluentHttpPP)

if (USE_STATIC_LINKING)
    if (MSVC)
        # MSVC specific static linking flag
        add_compile_options(/MT$<$<CONFIG:Debug>:d>)
    else()
        # GCC/Clang specific static linking flag
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++")
    endif()
endif()

include(CBuildKit)
include_directories(include)

add_subdirectory(src)
add_subdirectory(tests)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION include)

install_cfgpkg(fhpp 
"find_package(PkgConfig REQUIRED)
pkg_check_modules(OPENSSL REQUIRED openssl)

include(\${CMAKE_CURRENT_LIST_DIR}/fhpp-OpenSSLWithCrypto-targets.cmake)
include(\${CMAKE_CURRENT_LIST_DIR}/fhpp-fhpp-targets.cmake)
")