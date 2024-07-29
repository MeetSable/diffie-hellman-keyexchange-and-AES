#include "dhk.h"
#include "aes.h"

#include <iostream>

int main()
{
    std::cout   << "-------------------------------------\n"
                << "---------------SENDER----------------\n"
                << "-------------------------------------\n" << std::endl;
    const char* params_pem = "../shared/dhparams.pem";
    const char* receiver_key_pem = "../shared/receiver_pub.pem";
    const char* sender_key_pem = "../shared/sender_pub.pem";
    const char* secret_file = "secret.txt";
    const char* encrypted_file = "../shared/encrypted.en";
    const unsigned int aes_key_len = 32; //32 bytes, 256 bits

    std::cout << "Wait until the params have been generated by receiver (Press key to continue)\n";
    getc(stdin);

    size_t shared_key_len;
    EVP_PKEY* params = NULL;
    EVP_PKEY* receiver_key = NULL;
    // load public key and params
    load_dh_params(params_pem, &params);
    std::cout << "Params loaded\n\n\n";
    std::cout << "Generate sender's key and share (Press key to continue)\n";
    getc(stdin);
    // generate sender key from params
    EVP_PKEY *sender_key = generate_dh_public_key(params);
    save_public_key(sender_key, sender_key_pem);

    std::cout << "Sender's key shared\n\n\n";

    std::cout << "Load receiver's key and generate shared secret and aes key (press key to continue)\n";
    getc(stdin);

    receiver_key = load_public_key(receiver_key_pem);

    //derive shared secret
    unsigned char *shared_secret = derive_shared_secret(sender_key, receiver_key, shared_key_len);

    // derive aes key
    unsigned char *secret_aes_key = derive_aes_key(shared_secret, shared_key_len, aes_key_len);
    print_key_hex("Derived secret: ", shared_secret , shared_key_len );
    print_key_hex("Derived AES-key: ", secret_aes_key, 32);

    std::cout << "Encrypt and share the encrypted file (Press key to continue)\n";
    getc(stdin);
    // encrypt and send file
    encrypt_file(secret_file, encrypted_file, secret_aes_key, aes_key_len);

    std::cout << "encrypted file and public sender key sent!!!\n";

    // free pointers
    EVP_PKEY_free(params);
    EVP_PKEY_free(receiver_key);
    EVP_PKEY_free(sender_key);
    OPENSSL_free(shared_secret);
    OPENSSL_free(secret_aes_key);


    return 0;
}