add_library_ns(fhpp fhpp STATIC Request.cpp)
target_include_dir_iface(fhpp-fhpp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include include)
target_compile_features(fhpp-fhpp PUBLIC cxx_std_17)
install_target_and_headers(fhpp fhpp)

find_package(PkgConfig REQUIRED)
pkg_check_modules(OPENSSL REQUIRED openssl)

add_library_ns(fhpp OpenSSLWithCrypto INTERFACE)
target_link_libraries(fhpp-OpenSSLWithCrypto INTERFACE ${OPENSSL_LIBRARIES})
install_target_and_headers(fhpp OpenSSLWithCrypto)
add_dependencies(fhpp-fhpp fhpp-OpenSSLWithCrypto)

if(WIN32)
target_link_libraries(fhpp-OpenSSLWithCrypto INTERFACE ws2_32)
endif()

target_link_libraries(fhpp-fhpp fhpp-OpenSSLWithCrypto)