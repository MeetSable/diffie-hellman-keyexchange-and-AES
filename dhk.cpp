#include "dhk.h"

#include <iostream>
#include <fstream>
#include <openssl/dh.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/kdf.h>

#include <stdio.h>

void handle_error(const char* message)
{
	std::cerr << message << std::endl;
	ERR_print_errors_fp(stderr);
	// abort();
}

bool write_dh_to_file(const char* filename, const EVP_PKEY* params)
{
	BIO* bio = BIO_new(BIO_s_mem());
	if(!bio)
	{
		handle_error("Error creating BIO memory buffer.");
		return false;
	}

	if(!PEM_write_bio_Parameters(bio, params))
	{
		handle_error("Error writing DH parameters to memory buffer.");
		BIO_free(bio);
		return false;
	}

	std::ofstream pem_file(filename);
	if(!pem_file.is_open())
	{
		std::cerr << "Error opening PEM file: " << filename << std::endl;
		BIO_free(bio);
		return false;
	}

	char* bio_buf;
	long bio_len = BIO_get_mem_data(bio, &bio_buf);
	pem_file.write(bio_buf, bio_len);

	pem_file.close();
	BIO_free(bio);
	std::cout << "Diffie-Hellman params successfully written to " << filename << std::endl;
	return true;
}

bool generate_and_write_dh_params(const char* filename) {
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *params = NULL;
	BIO *bio = NULL;

	// Create a context for generating parameters
	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
	if (!ctx) {
		handle_error("Error creating EVP_PKEY_CTX.");
		return false;
	}

	// Initialize parameter generation
	if (EVP_PKEY_paramgen_init(ctx) != 1) {
		handle_error("Error initializing parameter generation.");
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	// Set parameters for key generation
	if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, 2048) != 1) {
		handle_error("Error setting DH prime length.");
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	// Generate parameters
	if (EVP_PKEY_paramgen(ctx, &params) != 1) {
		handle_error("Error generating DH parameters.");
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	// Create a BIO memory buffer
	bio = BIO_new(BIO_s_mem());
	if (!bio) {
		handle_error("Error creating BIO memory buffer.");
		EVP_PKEY_free(params);
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	// Write parameters to memory BIO
	if (!PEM_write_bio_Parameters(bio, params)) {
		handle_error("Error writing DH parameters to memory buffer.");
		BIO_free(bio);
		EVP_PKEY_free(params);
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	// Write the BIO memory buffer to a PEM file
	std::ofstream pem_file(filename);
	if (!pem_file.is_open()) {
		handle_error((std::string("Error opening PEM file: ") + std::string(filename)).c_str());
		BIO_free(bio);
		EVP_PKEY_free(params);
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	char *bio_buf;
	long bio_len = BIO_get_mem_data(bio, &bio_buf);
	pem_file.write(bio_buf, bio_len);

	pem_file.close();
	BIO_free(bio);
	EVP_PKEY_free(params);
	EVP_PKEY_CTX_free(ctx);

	std::cout << "Diffie-Hellman parameters successfully written to " << filename << std::endl;
	return true;
}

bool load_dh_params(const char* filename, EVP_PKEY **params)
{

	BIO* b = BIO_new(BIO_s_file());
	BIO_read_filename(b, filename);
	PEM_read_bio_Parameters(b, params);
	BIO_free(b);

	

	if (!*params) 
	{
		handle_error("Error reading DH parameters from PEM file.");
		return false;
	}

	return true;
}

EVP_PKEY* generate_dh_public_key(EVP_PKEY* params)
{
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(params, NULL);
	EVP_PKEY* dh_key = NULL;

	if(!ctx)
	{
		handle_error("Error creating key context.");
		return NULL;
	}

	if(EVP_PKEY_keygen_init(ctx) <= 0)
	{
		handle_error("Error intializing key generation.");
		return NULL;
	}

	if(EVP_PKEY_keygen(ctx, &dh_key) <= 0)
	{
		handle_error("Error generating key pair.");
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}
	EVP_PKEY_CTX_free(ctx);
	return dh_key;
}

bool save_public_key(EVP_PKEY* pubkey, const char* filename) {
    BIO* bio = BIO_new_file(filename, "w");
    if (!bio) {
        std::cerr << "Error creating BIO file." << std::endl;
        return false;
    }

    if (!PEM_write_bio_PUBKEY(bio, pubkey)) {
        std::cerr << "Error writing public key to PEM file." << std::endl;
        BIO_free(bio);
        return false;
    }

    BIO_free(bio);
    return true;
}

EVP_PKEY* load_public_key(const char* filename) {
    EVP_PKEY* pubkey = NULL;
    BIO* bio = BIO_new_file(filename, "r");
    if (!bio) {
        std::cerr << "Error creating BIO file." << std::endl;
        return NULL;
    }

    pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pubkey) {
        std::cerr << "Error reading public key from PEM file." << std::endl;
        BIO_free(bio);
        return NULL;
    }

    BIO_free(bio);
    return pubkey;
}

// Function to save a private key to a PEM file
bool save_private_key(EVP_PKEY* privkey, const char* filename) {
    BIO* bio = BIO_new_file(filename, "w");
    if (!bio) {
        std::cerr << "Error creating BIO file." << std::endl;
        return false;
    }

    if (!PEM_write_bio_PrivateKey(bio, privkey, NULL, NULL, 0, NULL, NULL)) {
        std::cerr << "Error writing private key to PEM file." << std::endl;
        BIO_free(bio);
        return false;
    }

    BIO_free(bio);
    return true;
}

// Function to load a private key from a PEM file
EVP_PKEY* load_private_key(const char* filename) {
    EVP_PKEY* privkey = NULL;
    BIO* bio = BIO_new_file(filename, "r");
    if (!bio) {
        std::cerr << "Error creating BIO file." << std::endl;
        return NULL;
    }

    privkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!privkey) {
        std::cerr << "Error reading private key from PEM file." << std::endl;
        BIO_free(bio);
        return NULL;
    }

    BIO_free(bio);
    return privkey;
}

// Function to derive the shared secret from my and peer's key
unsigned char* derive_shared_secret(EVP_PKEY *my_key, EVP_PKEY *peer_key, size_t &shared_key_len)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(my_key, NULL);
	unsigned char* shared_key = NULL;

	if(!ctx)
	{
		handle_error("Error creating sender context.");
		return NULL;
	}

	if(EVP_PKEY_derive_init(ctx) <= 0)
	{
		handle_error("Error intializing sender key derivation.");
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}

	if(EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0)
	{
		handle_error("Error setting sender peer key.");
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}

	if(EVP_PKEY_derive(ctx, NULL, &shared_key_len) <= 0)
	{
		handle_error("Error deriving sender key legth.");
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}

	shared_key = (unsigned char*)OPENSSL_malloc(shared_key_len);
	if(!shared_key)
	{
		handle_error("Error allocating memory for sender key.");
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}

	if(EVP_PKEY_derive(ctx, shared_key, &shared_key_len) <= 0) {
		handle_error("Error deriving sender key.");
		EVP_PKEY_CTX_free(ctx);
		OPENSSL_free(shared_key);
		return NULL;
	}
	EVP_PKEY_CTX_free(ctx);
	return shared_key;
}

// Function to derive AES key from shared secret using HKDF
unsigned char* derive_aes_key(const unsigned char *shared_secret, size_t shared_secret_len, size_t aes_key_len) {
    unsigned char *aes_key = (unsigned char*)OPENSSL_malloc(aes_key_len);
    if (!aes_key) {
        handle_error("Error allocating memory for AES key.");
        return NULL;
    }

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) {
        handle_error("Error creating HKDF context.");
        OPENSSL_free(aes_key);
        return NULL;
    }

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        handle_error("Error initializing HKDF.");
        EVP_PKEY_CTX_free(pctx);
        OPENSSL_free(aes_key);
        return NULL;
    }

    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) <= 0) {
        handle_error("Error setting HKDF mode.");
        EVP_PKEY_CTX_free(pctx);
        OPENSSL_free(aes_key);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
        handle_error("Error setting HKDF digest.");
        EVP_PKEY_CTX_free(pctx);
        OPENSSL_free(aes_key);
        return NULL;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, NULL, 0) <= 0) {
        handle_error("Error setting HKDF salt.");
        EVP_PKEY_CTX_free(pctx);
        OPENSSL_free(aes_key);
        return NULL;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, shared_secret, shared_secret_len) <= 0) {
        handle_error("Error setting HKDF key.");
        EVP_PKEY_CTX_free(pctx);
        OPENSSL_free(aes_key);
        return NULL;
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, NULL, 0) <= 0) {
        handle_error("Error adding HKDF info.");
        EVP_PKEY_CTX_free(pctx);
        OPENSSL_free(aes_key);
        return NULL;
    }

    if (EVP_PKEY_derive(pctx, aes_key, &aes_key_len) <= 0) {
        handle_error("Error deriving AES key.");
        EVP_PKEY_CTX_free(pctx);
        OPENSSL_free(aes_key);
        return NULL;
    }

    EVP_PKEY_CTX_free(pctx);
    return aes_key;
}

void print_key_hex(const char* message, unsigned char* key_arr, size_t key_len)
{
    std::cout << message;
    for(int i = 0 ; i < key_len ; i++)
    {
        printf("%.2X", key_arr[i]);
    }
    std::cout << std::endl;
}