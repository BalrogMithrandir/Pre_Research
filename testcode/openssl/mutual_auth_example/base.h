#pragma once

#include <openssl/ssl.h>
#include <iostream>
#include <memory>
typedef std::unique_ptr<uint8_t[]> ByteArray;

int loadca_from_mem(SSL_CTX* ctx, const uint8_t* ca, size_t ca_len);
int set_accept_client_cn(SSL* ssl, const std::string& accept_cn); 
int set_accept_client_ca(SSL_CTX* ctx, const std::string& accept_ca_path);
int init_cert_key_ca(SSL_CTX* ctx, const std::string& cert, const std::string& key, const std::string ca); 
void ShowCerts(SSL * ssl);
int check_cert_cn(X509_STORE_CTX *ctx, const std::string& expect_cn);
bool read_file(const std::string& source, ByteArray& buf, size_t& size); 
