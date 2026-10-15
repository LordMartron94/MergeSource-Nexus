file(GLOB_RECURSE nexus_sources CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c"
)
add_library(nexus SHARED ${nexus_sources})
add_library(Nexus::Nexus ALIAS nexus)
target_include_directories(nexus PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(nexus
    PRIVATE MergeSource::Options Threads::Threads ${CMAKE_DL_LIBS}
    PUBLIC nexus_c89_extensions External::stb External::xxhash
)
if(UNIX)
    target_link_libraries(nexus PRIVATE m)
endif()

# These public-header switches must match in Nexus and its consumers.
target_compile_definitions(nexus PUBLIC
    NEXUS_DEVELOPER_MODE=$<IF:$<CONFIG:Debug>,1,0>
    NEXUS_MEMORY_DEBUG_MODE=$<IF:$<CONFIG:Debug>,1,0>
    NEXUS_MEMORY_TRACING=$<IF:$<CONFIG:Debug>,1,0>
)
# Preserve the archived build's C89 extension flags for this public header.
# Keep them after the general warning policy, as in the archived build.
add_library(nexus_c89_extensions INTERFACE)
target_compile_options(nexus_c89_extensions INTERFACE
    "$<$<C_COMPILER_ID:GNU,Clang>:-Wno-long-long;-Wno-variadic-macros>"
    "$<$<C_COMPILER_ID:Clang>:-fdeclspec;-Wno-gnu-zero-variadic-macro-arguments>"
)

file(GLOB nexus_test_sources CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.c"
)
if(BUILD_TESTING AND nexus_test_sources)
    add_executable(nexus_tests ${nexus_test_sources})
    target_link_libraries(nexus_tests PRIVATE MergeSource::Options Nexus::Nexus)
    add_test(NAME nexus_tests COMMAND nexus_tests)
endif()
