#pragma once
#include <cstddef>

const size_t AES_BLOCK_SIZE = 16;

bool save_aes_key(const unsigned char* aes_key, size_t key_len, const char* filename);
unsigned char* load_aes_key(const char* filename, size_t key_len);
bool encrypt_file(const char* input_filename, const char* output_filename, const unsigned char* aes_key, size_t key_len);
bool decrypt_file(const char* input_filename, const char* output_filename, const unsigned char* aes_key, size_t key_len);