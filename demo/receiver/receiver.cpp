#include "dhk.h"
#include "aes.h"

#include <iostream>

int main()
{
    std::cout   << "-------------------------------------\n"
                << "--------------RECEIVER---------------\n"
                << "-------------------------------------\n" << std::endl;

    const char* params_pem = "../shared/dhparams.pem";
    const char* reciever_key_pem = "../shared/receiver_pub.pem";
    const char* sender_key_pem = "../shared/sender_pub.pem";
    const char* encrypted_file = "../shared/encrypted.en";
    const char* secret_file = "secret.txt";
    const unsigned int aes_key_len = 32; // 32 bytes , 256 bits

    std::cout << "Generating params for Diffie-Hellman exchange\n";

    // generate parameters for dhk exchange
    generate_and_write_dh_params(params_pem);

    std::cout << "Generate receiver's keys and share (Press any key)\n";
    getc(stdin);

    // load the dh params
    size_t shared_key_len;
    EVP_PKEY* params = NULL;
    load_dh_params(params_pem, &params);

    EVP_PKEY *receiver_key = generate_dh_public_key(params);
    save_public_key(receiver_key, reciever_key_pem);
    std::cout << "Public keys shared\n" << std::endl;
    std::cout << "Load Sender key, derive shared secret and AES key (Press any key)\n" << std::endl;
    getc(stdin);
    
    // load public sender key
    EVP_PKEY *sender_key = load_public_key(sender_key_pem);

    // derive shared secret
    unsigned char* shared_secret = derive_shared_secret(receiver_key, sender_key, shared_key_len);

    // derive aes key
    unsigned char* secret_aes_key = derive_aes_key(shared_secret, shared_key_len, aes_key_len);

    print_key_hex("Derived secret: ", shared_secret , shared_key_len );
    print_key_hex("Derived AES-key: ", secret_aes_key, 32);

    std::cout << "Decrypt the shared file and save (Press key to continue)\n";
    getc(stdin);

    // decrypt the file
    decrypt_file(encrypted_file, secret_file, secret_aes_key, aes_key_len);

    std::cout << "File decrpted and saved in receiver/secret.txt\n";

    EVP_PKEY_free(params);
    EVP_PKEY_free(receiver_key);
    EVP_PKEY_free(sender_key);
    OPENSSL_free(shared_secret);


    return 0;
}
