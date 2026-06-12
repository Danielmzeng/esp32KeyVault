idf_component_register(SRCS "vault.c"
                       INCLUDE_DIRS "include"
                       REQUIRES vault_crypto vault_store)
