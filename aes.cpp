#include "aes.h"

#include <iostream>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

// Function to save AES key to a file
bool save_aes_key(const unsigned char* aes_key, size_t key_len, const char* filename) {
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error opening file for writing AES key." << std::endl;
        return false;
    }

    file.write(reinterpret_cast<const char*>(aes_key), key_len);
    if (!file) {
        std::cerr << "Error writing AES key to file." << std::endl;
        file.close();
        return false;
    }

    file.close();
    return true;
}

// Function to load AES key from a file
unsigned char* load_aes_key(const char* filename, size_t key_len) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error opening file for reading AES key." << std::endl;
        return NULL;
    }

    unsigned char* aes_key = (unsigned char*)OPENSSL_malloc(key_len);
    if (!aes_key) {
        std::cerr << "Error allocating memory for AES key." << std::endl;
        file.close();
        return NULL;
    }

    file.read(reinterpret_cast<char*>(aes_key), key_len);
    if (!file) {
        std::cerr << "Error reading AES key from file." << std::endl;
        file.close();
        OPENSSL_free(aes_key);
        return NULL;
    }

    file.close();
    return aes_key;
}

// Function to encrypt data from a file to a new file
bool encrypt_file(const char* input_filename, const char* output_filename, const unsigned char* aes_key, size_t key_len) {
    std::ifstream input_file(input_filename, std::ios::binary);
    std::ofstream output_file(output_filename, std::ios::binary);
    if (!input_file.is_open() || !output_file.is_open()) {
        std::cerr << "Error opening input or output file." << std::endl;
        return false;
    }

    // Generate a random IV
    unsigned char iv[AES_BLOCK_SIZE];
    if (!RAND_bytes(iv, sizeof(iv))) {
        std::cerr << "Error generating random IV." << std::endl;
        return false;
    }

    // Write the IV to the output file
    output_file.write(reinterpret_cast<const char*>(iv), sizeof(iv));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating cipher context." << std::endl;
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv) != 1) {
        std::cerr << "Error initializing encryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    unsigned char buffer[AES_BLOCK_SIZE];
    unsigned char ciphertext[AES_BLOCK_SIZE + AES_BLOCK_SIZE];
    int len, ciphertext_len;

    while (input_file.read(reinterpret_cast<char*>(buffer), sizeof(buffer))) {
        if (EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, buffer, sizeof(buffer)) != 1) {
            std::cerr << "Error during encryption." << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        output_file.write(reinterpret_cast<const char*>(ciphertext), ciphertext_len);
    }

    if (input_file.gcount() > 0) {
        if (EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, buffer, input_file.gcount()) != 1) {
            std::cerr << "Error during encryption of final block." << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        output_file.write(reinterpret_cast<const char*>(ciphertext), ciphertext_len);
    }

    if (EVP_EncryptFinal_ex(ctx, ciphertext, &ciphertext_len) != 1) {
        std::cerr << "Error finalizing encryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    output_file.write(reinterpret_cast<const char*>(ciphertext), ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// Function to decrypt data from a file to a new file
bool decrypt_file(const char* input_filename, const char* output_filename, const unsigned char* aes_key, size_t key_len) {
    std::ifstream input_file(input_filename, std::ios::binary);
    std::ofstream output_file(output_filename, std::ios::binary);
    if (!input_file.is_open() || !output_file.is_open()) {
        std::cerr << "Error opening input or output file." << std::endl;
        return false;
    }

    // Read the IV from the input file
    unsigned char iv[AES_BLOCK_SIZE];
    input_file.read(reinterpret_cast<char*>(iv), sizeof(iv));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating cipher context." << std::endl;
        return false;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv) != 1) {
        std::cerr << "Error initializing decryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    unsigned char buffer[AES_BLOCK_SIZE];
    unsigned char plaintext[AES_BLOCK_SIZE + AES_BLOCK_SIZE];
    int len, plaintext_len;

    while (input_file.read(reinterpret_cast<char*>(buffer), sizeof(buffer))) {
        if (EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, buffer, sizeof(buffer)) != 1) {
            std::cerr << "Error during decryption." << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        output_file.write(reinterpret_cast<const char*>(plaintext), plaintext_len);
    }

    if (input_file.gcount() > 0) {
        if (EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, buffer, input_file.gcount()) != 1) {
            std::cerr << "Error during decryption of final block." << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        output_file.write(reinterpret_cast<const char*>(plaintext), plaintext_len);
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext, &plaintext_len) != 1) {
        std::cerr << "Error finalizing decryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    output_file.write(reinterpret_cast<const char*>(plaintext), plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}