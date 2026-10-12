cmake_minimum_required(VERSION 3.14)

project(bnt
    VERSION 0.1.0
    DESCRIPTION "Verifier-friendly packet parsing & rewriting for eBPF (XDP/TC)"
    HOMEPAGE_URL "https://github.com/bonetlabs/bonet"
    LANGUAGES C)

# GNUInstallDirs must be included before target_include_directories so that
# CMAKE_INSTALL_INCLUDEDIR is defined when the $<INSTALL_INTERFACE:...> include
# path is recorded; otherwise the exported bnt::bnt target propagates no -I.
include(GNUInstallDirs)

# bnt is header-only: an INTERFACE target that only propagates the include path.
# It does NOT compile BPF objects — consumers build those with their own
# `clang -target bpf` invocation; this target just makes the headers available
# (e.g. target_link_libraries(myprog PRIVATE bnt::bnt) adds -I.../include).
add_library(bnt INTERFACE)
add_library(bnt::bnt ALIAS bnt)

target_include_directories(bnt INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

# Only install/export when bnt is the top-level project (not when add_subdirectory'd).
if(PROJECT_IS_TOP_LEVEL OR CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    include(CMakePackageConfigHelpers)

    # Headers
    install(DIRECTORY src/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING PATTERN "bnt_*.h")

    # Export target for find_package(bnt) / target_link_libraries(bnt::bnt)
    install(TARGETS bnt EXPORT bntTargets)
    install(EXPORT bntTargets
        FILE bntTargets.cmake
        NAMESPACE bnt::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/bnt)

    configure_package_config_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/bntConfig.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/bntConfig.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/bnt)
    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/bntConfigVersion.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
        ARCH_INDEPENDENT)
    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/bntConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/bntConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/bnt)

    # pkg-config (for Makefile / non-CMake consumers: `pkg-config --cflags bnt`)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/bnt.pc.in
        ${CMAKE_CURRENT_BINARY_DIR}/bnt.pc @ONLY)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/bnt.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
endif()
