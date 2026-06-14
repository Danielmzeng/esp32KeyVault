idf_component_register(SRCS "vault.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES vault_crypto vault_store vault_error)
