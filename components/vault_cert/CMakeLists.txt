idf_component_register(SRCS "vault_cert.c"
                       INCLUDE_DIRS "include"
                       REQUIRES mbedtls vault_store)
