idf_component_register(INCLUDE_DIRS "include")

# Embedded build: no POSIX signal handlers, no std::thread, no colored TTY.
target_compile_definitions(${COMPONENT_LIB} INTERFACE
    DOCTEST_CONFIG_NO_POSIX_SIGNALS
    DOCTEST_CONFIG_NO_MULTITHREADING)
