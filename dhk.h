#pragma once

#include <openssl/evp.h>
#include <openssl/dh.h>

#ifndef NBITS
#define NBITS 256
#endif

#define SUCCESS 0
#define FAILURE 1

enum dh_type {
    PARAMS = 1,
    KEY = 2
};

void handle_error(const char* message);
bool write_dh_to_file(const char* filename, const EVP_PKEY* params);
bool generate_and_write_dh_params(const char* filename);


bool load_dh_params(const char* filename, EVP_PKEY **params);
EVP_PKEY* generate_dh_public_key(EVP_PKEY *params);
bool save_public_key(EVP_PKEY* pubkey, const char* filename);
EVP_PKEY* load_public_key(const char* filename);
bool save_private_key(EVP_PKEY* privkey, const char* filename);
EVP_PKEY* load_private_key(const char* filename);

bool derive_dh_public_key(EVP_PKEY_CTX *ctx, EVP_PKEY *peer_key);
unsigned char* derive_shared_secret(EVP_PKEY *my_key, EVP_PKEY *peer_key, size_t &shared_key_len);
unsigned char* derive_aes_key(const unsigned char *shared_secret, size_t shared_secret_len, size_t aes_key_len);

void print_key_hex(const char* message, unsigned char* key_arr, size_t key_len);