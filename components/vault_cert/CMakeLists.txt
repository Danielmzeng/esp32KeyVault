idf_component_register(SRCS "vault_cert.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES mbedtls vault_store vault_error)
