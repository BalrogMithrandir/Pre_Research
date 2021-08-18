#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <iostream>
#include <assert.h>
#include <fstream>
#include <fcntl.h>
#include "cfg.h"
#include "base.h"

#if 1 
static void free_x509(X509* x509) {
    if (NULL != x509) {
        X509_free(x509);
    }
}
static void free_rsa(RSA* rsa) {
    if (NULL != rsa) {
        RSA_free(rsa);
    }
}
static void free_bio(BIO* bio) {
    if (NULL != bio) {
        BIO_free(bio);
    }
}
static void free_x509_store(X509_STORE* x509_store) {
    if (NULL != x509_store) {
        X509_STORE_free(x509_store);
    }
}
static void free_evp_key(EVP_PKEY* evp_key) {
    if (NULL != evp_key) {
        EVP_PKEY_free(evp_key);
    }
}
bool load_cert_chain_from_shared_mem(SSL_CTX *context, const char *cert_buffer)
{
    BIO *cbio = BIO_new_mem_buf((void*)cert_buffer, -1);
    if (!cbio)
        return false;

    X509_INFO *itmp;
    int i;
    STACK_OF(X509_INFO) *inf = PEM_X509_INFO_read_bio(cbio, NULL, NULL, NULL);

    if (!inf) {
        BIO_free(cbio);
        return false;
    }

    /* Iterate over contents of the PEM buffer, and add certs. */
    bool first = true;
    for (i = 0; i < sk_X509_INFO_num(inf); i++) {
        itmp = sk_X509_INFO_value(inf, i);
        if (itmp->x509)
        {
   /* First cert is server cert. Remaining, if any, are intermediate certs. */
   if (first)
   {
       first = false;

       /*
        * Set server certificate. Note that this operation increments the
        * reference count, which means that it is okay for cleanup to free it.
        */
       if (!SSL_CTX_use_certificate(context, itmp->x509))
  goto Error;

       if (ERR_peek_error() != 0)
  goto Error;

       /* Get ready to store intermediate certs, if any. */
       SSL_CTX_clear_chain_certs(context);
   }
   else
   {
       /* Add intermediate cert to chain. */
       if (!SSL_CTX_add0_chain_cert(context, itmp->x509))
  goto Error;

       /*
        * Above function doesn't increment cert reference count. NULL the info
        * reference to it in order to prevent it from being freed during cleanup.
        */
       itmp->x509 = NULL;
   }
        }
    }

    sk_X509_INFO_pop_free(inf, X509_INFO_free);
    BIO_free(cbio);

    return true;

Error:
    sk_X509_INFO_pop_free(inf, X509_INFO_free);
    BIO_free(cbio);

    return false;
}

static X509* buffer2x509(const uint8_t* cert, size_t len) {
    /*read the cert and decode it*/
    BIO *b = BIO_new_mem_buf((void *)cert, len);
    if (NULL == b) {
        return NULL;
    }
    X509* x509 = PEM_read_bio_X509(b, NULL, NULL, NULL);
    if (NULL == x509) {
        BIO_free(b);
        return NULL;
    }
    BIO_free(b);
    return x509;
}

static RSA* buffer2rsa(const uint8_t* key, size_t key_len) {
    BIO* kbio = BIO_new_mem_buf((void*)key, key_len);
    return PEM_read_bio_RSAPrivateKey(kbio, NULL, 0, NULL);
}

static EVP_PKEY* buffer2evpkey(const uint8_t* key, size_t key_len) {
    EVP_PKEY* EVP_PKEY_key = d2i_AutoPrivateKey(NULL, (const unsigned char **)&key, key_len);
    if (NULL == EVP_PKEY_key) {      
        /*charge if the cert is not in PEM format, transform it*/        
        BIO *b = BIO_new_mem_buf((void *)key, key_len);
        EVP_PKEY_key = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);     
        BIO_free(b);
        if (NULL == EVP_PKEY_key) {  
            printf("PEM_read_bio_PrivateKey failed\n");
            return NULL;   
        } 
    }     
    return NULL;   
}     

static int check(X509_STORE *ctx, X509* cert)
{
    int ret = -1;
    X509_STORE_CTX *csc;
    do {
        csc = X509_STORE_CTX_new();
        if (csc == NULL) {
   break;
        }
        X509_STORE_set_flags(ctx, 0);
        if (!X509_STORE_CTX_init(csc, ctx, cert, 0)) {
   break;
        }
        
        ret = X509_verify_cert(csc);
    } while (0);
    if (NULL != csc) {
        X509_STORE_CTX_free(csc);
    }
    return ret;  /*1:: check ok*/
}

int rsa_cert_verify(const uint8_t* ca, size_t ca_len, const uint8_t* cert, size_t cert_len) {
    X509_STORE *cert_ctx = NULL;
    X509_LOOKUP *lookup = NULL;
    X509 *ca_x509 = NULL;
    X509 *cert_x509 = NULL;
    int rtn = 1;
    do {
        cert_ctx = X509_STORE_new();
        if (cert_ctx == NULL) {
   rtn = -1;
   break;
        }
        OpenSSL_add_all_algorithms();
        lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file());
        if (lookup == NULL) {
   rtn = -1;
   break;
        }
        ca_x509 = buffer2x509(ca, ca_len);
        X509_STORE_add_cert(cert_ctx, ca_x509);
        
        /*if(!X509_LOOKUP_load_file(lookup, CAfile, X509_FILETYPE_PEM)) {
   break;
        }*/
        
        lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_hash_dir());
        if (lookup == NULL) {
   rtn = -1;
   break;
        }
        X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);
        cert_x509 = buffer2x509(cert, cert_len);
        if (1 != check(cert_ctx, cert_x509)) {
   rtn = -1;
        }
    } while (0);
    free_x509_store(cert_ctx);
    free_x509(ca_x509);
    free_x509(cert_x509);
    return rtn;
}
#endif
#if 1
int loadca_from_mem(SSL_CTX *ctx, const uint8_t* ca, size_t ca_len) {
    BIO *b = BIO_new_mem_buf((void *)ca, ca_len);
    if (NULL == b) {
        return 0;
    }
     
    X509_INFO *itmp;
    int i, count = 0;
    X509_STORE* store_ctx = SSL_CTX_get_cert_store(ctx);

    STACK_OF(X509_INFO)* inf = PEM_X509_INFO_read_bio(b, NULL, NULL, NULL);
    BIO_free(b);
    if (!inf) {
        return 0;
    }
    for (i = 0; i < sk_X509_INFO_num(inf); i++) {
        itmp = sk_X509_INFO_value(inf, i);
        if (itmp->x509) {
   X509_STORE_add_cert(store_ctx, itmp->x509);
   count++;
        }
        if (itmp->crl) {
   X509_STORE_add_crl(store_ctx, itmp->crl);
   count++;
        }
    }
    sk_X509_INFO_pop_free(inf, X509_INFO_free);
    return count;
}
#endif
int set_accept_client_ca(SSL_CTX* ctx, const std::string& accept_ca_path) {
    STACK_OF(X509_NAME) *accept_CA_stack = SSL_load_client_CA_file(ACCEPT_CLIENT_CA);
    if (NULL == accept_CA_stack) {
        printf("get accept_CA_stack fialed\n");
        ERR_print_errors_fp(stdout);
        return -1;    
    }

    SSL_CTX_set_client_CA_list(ctx, accept_CA_stack);
    return 1;
}

int set_accept_client_cn(SSL* ssl, const std::string& accept_cn) {
    if (!X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), accept_cn.c_str(), accept_cn.size())) {
        ERR_print_errors_fp(stdout);
        return -1;
    }
    return 1;
}

int init_cert_key_ca(SSL_CTX* ctx, const std::string& cert, const std::string& key, const std::string ca) {
#if defined(LOAD_FROM_MEMORY)
    ByteArray ca_buf;
    size_t ca_len = 0;
    read_file(ca, ca_buf, ca_len);
    
    ByteArray cert_buf;
    size_t cert_len = 0;
    read_file(cert, cert_buf, cert_len);
   
    ByteArray key_buf;
    size_t key_len = 0;
    read_file(key, key_buf, key_len);

    // 设置信任根证书
    loadca_from_mem(ctx, ca_buf.get(), ca_len); 

    X509* b_cert = buffer2x509(cert_buf.get(), cert_len);
    SSL_CTX_use_certificate(ctx, b_cert);

    RSA* r_key = buffer2rsa(key_buf.get(), key_len);
    SSL_CTX_use_RSAPrivateKey(ctx, r_key);

//    EVP_PKEY* e_key = buffer2evpkey(key_buf.get(), key_len);
//    SSL_CTX_use_PrivateKey(ctx, e_key);
#else
    // 设置信任根证书
    if (SSL_CTX_load_verify_locations(ctx, ca.c_str(), NULL) <= 0) {
        ERR_print_errors_fp(stdout);
        return -1;
    }

    /* 载入用户的数字证书， 此证书用来发送给客户端。 证书里包含有公钥 */
    if (SSL_CTX_use_certificate_file(ctx, cert.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        return -1;
    }

    /* 载入用户私钥 */
    if (SSL_CTX_use_PrivateKey_file(ctx, key.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        return -1;
    }
#endif 

    /* 检查用户私钥是否正确 */
    if (!SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stdout);
        return -1;
    }
    return 1;
}

void ShowCerts(SSL * ssl) {
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    
    // SSL_get_verify_result()是重点，SSL_CTX_set_verify()只是配置启不启用并没有执行认证，调用该函数才会真证进行证书认证
    // 如果验证不通过，那么程序抛出异常中止连接

    /*如果没有证书，SSL_get_verify_result也会返回ok，因为没有发生错误。所以在使用该API时，
    一定要先调用SSL_get_peer_certificate。这个是api的bug*/
    if(SSL_get_verify_result(ssl) == X509_V_OK) {
        printf("证书验证通过\n");
    } else {
        printf("证书验证失败\n");
    }
    if (cert != NULL) {
        printf("数字证书信息:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("证书: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("颁发者: %s\n", line);
        free(line);
        X509_free(cert);
    } else {
        printf("无证书信息！\n");
    }
}

int check_cert_cn(X509_STORE_CTX *ctx, const std::string& expect_cn) {
    char CN[256] = {0};
    X509* cert = X509_STORE_CTX_get_current_cert(ctx);

    int rslt = 0;
    if (cert != NULL) {
//        printf("数字证书信息:\n");
        
        /*获取对端证书的CN字段*/
        X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, CN, sizeof(CN));
        
        /*校验CN是否与目标域名一致：一致，返回1；不一致，返回0*/
        if (0 == strcmp(CN, expect_cn.c_str())) {
   rslt = 1;
        } else {
   printf("client CA cert's cn %s is unmatch with expect %s\n", CN, expect_cn.c_str());
   rslt = 0;
        }
       // X509_free(cert);
    } else {
        printf("无证书信息！\n");
        rslt = 0;
    }
    
    return rslt;
}

bool read_file(const std::string& source, ByteArray& buf, size_t& size) {   
    assert(!source.empty()); 
  
    /*ios::ate - location the end of the file to get file size by tellg()*/       
    std::ifstream in(source.c_str(), std::ios::in | std::ios::binary | std::ios::ate);     
  
    if (!in.is_open()) {     
        printf("cann\'t open the file, file path is %s\n", source.c_str());
        return false;        
    }      
  
    size = in.tellg();       
    in.seekg(0, std::ios::beg);       
  
    buf.reset(new uint8_t[size]);     
    if (!in.read(reinterpret_cast<char*>(buf.get()), size)) {    
        printf("read file %s failed, expect read size[%zu], get[%ld]\n", source.c_str(), size, in.gcount());
        in.close(); 
        return false;        
    }      
  
    in.close();     
    return true;    
} 

