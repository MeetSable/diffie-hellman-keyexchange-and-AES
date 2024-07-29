#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "dhk.h"
#include "aes.h"

int test_dh_and_aes_gen() {
	const char* pem_filename = "dhparams.pem";
	size_t shared_key_len;

	// Load Diffie-Hellman parameters from PEM file
	EVP_PKEY *params = NULL;
	load_dh_params(pem_filename, &params);
	if (!params) {
		std::cerr << "Failed to load DH parameters from PEM file." << std::endl;
		return 1;
	}

	// Generate DH public keys for sender and receiver
	EVP_PKEY *sender_key = generate_dh_public_key(params);
	EVP_PKEY *receiver_key = generate_dh_public_key(params);
	if (!sender_key || !receiver_key) {
		std::cerr << "Failed to generate DH public keys." << std::endl;
		EVP_PKEY_free(params);
		return 1;
	}
	save_public_key(sender_key, "sender.pem");
	save_private_key(sender_key, "sender_priv.pem");
	EVP_PKEY_free(sender_key);
	sender_key = load_public_key("sender.pem");
	std::cout << "loaded!!!";
	// Derive shared secret on sender side
	unsigned char *shared_secret_sender = derive_shared_secret(receiver_key, sender_key, shared_key_len);
	if (!shared_secret_sender) {
		std::cerr << "Failed to derive shared secret on sender side." << std::endl;
		EVP_PKEY_free(sender_key);
		EVP_PKEY_free(receiver_key);
		EVP_PKEY_free(params);
		return 1;
	}

	// Derive shared secret on receiver side
	unsigned char *shared_secret_receiver = derive_shared_secret(receiver_key, sender_key, shared_key_len);
	if (!shared_secret_receiver) {
		std::cerr << "Failed to derive shared secret on receiver side." << std::endl;
		EVP_PKEY_free(sender_key);
		EVP_PKEY_free(receiver_key);
		EVP_PKEY_free(params);
		OPENSSL_free(shared_secret_sender);
		return 1;
	}

	// Compare shared secrets
	if (memcmp(shared_secret_sender, shared_secret_receiver, shared_key_len) != 0) {
		std::cerr << "Error: Shared secrets do not match." << std::endl;
	}
	else
	{
		std::cout << "Shared secrets match." << std::endl;
		std::cout << "Shared Key: ";
		for (size_t i = 0; i < shared_key_len; ++i) {
			printf("%02X", shared_secret_sender[i]);
		}
		std::cout << std::endl;
	}

	size_t aes_key_len = 32; // in bytes
	unsigned char *shared_aes_key_sender = derive_aes_key(shared_secret_sender, shared_key_len, aes_key_len);

	save_aes_key(shared_aes_key_sender, aes_key_len, "aes_key.bin");

	// Clean up
	EVP_PKEY_free(sender_key);
	EVP_PKEY_free(receiver_key);
	EVP_PKEY_free(params);
	OPENSSL_free(shared_secret_sender);
	OPENSSL_free(shared_secret_receiver);
	return 0;
}

int test_aes_encryption_decryption()
{
	size_t key_len = 32;
	unsigned char* aes_key = load_aes_key("aes_key.bin", 32);
	if(!encrypt_file("test_file.txt", "test_file.en", aes_key, key_len)) return -1;
	if(!decrypt_file("test_file.en", "test_file_dec.txt", aes_key, key_len)) return -1;
	return 0;
}

int main()
{
	return test_aes_encryption_decryption();
}
