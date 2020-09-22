// 证书、私钥、公钥都是PEM格式文件

// 编译命令：gcc -o test test_pubkey_pem.c -lcrypto -std=c99

#include <openssl/x509.h>
#include <openssl/pem.h>
#include<stdio.h>
#include<string.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/time.h>
#include <time.h>
// 文件路径
char cert_filename[] = "../testcert/server.cer";
//char pubkey_filename[] = "../testcert/server.key";
char prikey_filename[] = "../testcert/server.key";

int rsa_sign()
{
    struct timeval curr;

    uint64_t time_pub_enc_begin = 0;
    uint64_t time_pub_enc_end = 0;
    uint64_t time_pub_dec_begin = 0;
    uint64_t time_pub_dec_end = 0;
    uint64_t time_pri_enc_begin = 0;
    uint64_t time_pri_enc_end = 0;
    uint64_t time_pri_dec_begin = 0;
    uint64_t time_pri_dec_end = 0;

    uint64_t time_pub_enc_use = 0;
    uint64_t time_pub_dec_use = 0;
    uint64_t time_pri_enc_use = 0;
    uint64_t time_pri_dec_use = 0;

    int times = 0;

    EVP_PKEY *pkey;
    BIO *pubkey_bio;
    BIO *prikey_bio;
    BIO *cert;

    /************ 从证书中提取公钥 ****************/
    // 打开证书文件
    cert = BIO_new_file(cert_filename, "r");

    // 读入X509证书
    X509 * x_cert = PEM_read_bio_X509(cert, NULL, NULL, NULL);
    BIO_free(cert);

    // 提取出密钥EVP_PKEY结构
    pkey = X509_get_pubkey(x_cert);

    // 提取出RSA结构的公钥
    RSA* rsa_from_cert = EVP_PKEY_get1_RSA(pkey);
    X509_free(x_cert);
    EVP_PKEY_free(pkey);

    // 打印公钥的值
    BIO * print_out = BIO_new(BIO_s_file());
    BIO_set_fp(print_out,stdout,BIO_NOCLOSE);
    //RSA_print(print_out, rsa_from_cert, 0);

    int ret;

    /************ 从私钥文件中提取私钥 ****************/
    prikey_bio = BIO_new_file(prikey_filename, "r");
    pkey = PEM_read_bio_PrivateKey(prikey_bio, NULL, NULL, NULL);
    RSA *pri_rsa = EVP_PKEY_get1_RSA(pkey);

    /*********** 预分配控件 ******************/
    // 根据RSA公钥长度分配RSA加密输出空间
    int keysize = RSA_size(rsa_from_cert);
    printf("keysize:%d\n", keysize);
    unsigned char *rsa_out_cert = OPENSSL_malloc(keysize);
    unsigned char *dec_out = OPENSSL_malloc(keysize);
    unsigned char *sign_out = OPENSSL_malloc(keysize);
    unsigned char *verify_out = OPENSSL_malloc(keysize);


    /*********** RSA公钥加密 ******************/
    char rsa_in[] = "testing";
    int rsa_inlen = strlen(rsa_in);

    // 使用RKCS#1填充标准
    int pad = RSA_PKCS1_PADDING;
    
    gettimeofday(&curr, NULL);
    int64_t begin = (curr.tv_sec) * 1000000 + curr.tv_usec;
    printf("begin %lld\n", begin);
    while (times < 1000) {
        gettimeofday(&curr, NULL);
        time_pub_enc_begin = (curr.tv_sec) * 1000000 + curr.tv_usec;
        int rsa_outlen_cert = RSA_public_encrypt(rsa_inlen, rsa_in, rsa_out_cert, rsa_from_cert, pad);
        gettimeofday(&curr, NULL);
        time_pub_enc_end = (curr.tv_sec) * 1000000 + curr.tv_usec;

        time_pub_enc_use += (time_pub_enc_end - time_pub_enc_begin);

    /*    printf("rsa_outlen_cert is: %d\n", rsa_outlen_cert);
        for(int i=0; i<rsa_outlen_cert; i++){
            printf("%02x", rsa_out_cert[i]);
            if((i+1)%16 == 0)
                printf("\n");
        }*/
        //printf("\n");

        /*********** RSA私钥解密 ******************/
        gettimeofday(&curr, NULL);
        time_pri_dec_begin = (curr.tv_sec) * 1000000 + curr.tv_usec;
        int dec_len = RSA_private_decrypt(rsa_outlen_cert, rsa_out_cert, dec_out, pri_rsa, pad);
        gettimeofday(&curr, NULL);
        time_pri_dec_end = (curr.tv_sec) * 1000000 + curr.tv_usec;

        time_pri_dec_use += (time_pri_dec_end - time_pri_dec_begin);

        if(!memcmp(rsa_in, dec_out, dec_len)){
            //printf("decrypt success!\n");
        }else{
            //printf("decrypt fail!\n");
        }
        //printf("dec_len is %d\n", dec_len);

        /*********** RSA私钥签名 *******************/
        gettimeofday(&curr, NULL);
        time_pri_enc_begin = (curr.tv_sec) * 1000000 + curr.tv_usec;
        int sign_len = RSA_private_encrypt(rsa_inlen, rsa_in, sign_out, pri_rsa, pad);
        gettimeofday(&curr, NULL);
        time_pri_enc_end = (curr.tv_sec) * 1000000 + curr.tv_usec;

        time_pri_enc_use += (time_pri_enc_end - time_pri_enc_begin);
    /*
        printf("sign_len is: %d\n", sign_len);
        for(int i=0; i<sign_len; i++){
            printf("%02x", sign_out[i]);
            if((i+1)%16 == 0)
                printf("\n");
        }
        printf("\n");*/

        /********** RSA公钥验签 *******************/
        gettimeofday(&curr, NULL);
        time_pub_dec_begin = (curr.tv_sec) * 1000000 + curr.tv_usec;
        int verify_len = RSA_public_decrypt(sign_len, sign_out, verify_out, rsa_from_cert, pad);
        gettimeofday(&curr, NULL);
        time_pub_dec_end = (curr.tv_sec) * 1000000 + curr.tv_usec;

        time_pub_dec_use += (time_pub_dec_end - time_pub_dec_begin);

        //printf("verify_len is %d\n", verify_len);
        if(!memcmp(rsa_in, verify_out, verify_len)){
            //printf("verify success!\n");
        }else{
            //printf("verify fail!\n");
        }
        times++;
        //printf("%d\n", times);
    }
    gettimeofday(&curr, NULL);
    int64_t end = (curr.tv_sec) * 1000000 + curr.tv_usec;
    printf("end %lld\n", end);
    printf("pub enc : %lld, pri dec: %lld, pri enc: %lld, pub dec: %lld\n", 
        time_pub_enc_use/1000,  time_pri_dec_use/1000, time_pri_enc_use/1000, time_pub_dec_use/1000);

    /***********释放变量清理空间 ****************/
    OPENSSL_free(dec_out);
    OPENSSL_free(rsa_out_cert);
    OPENSSL_free(sign_out);
    OPENSSL_free(verify_out);
    /*BIO_free(pubkey_bio);*/
    BIO_free(prikey_bio);

    EVP_PKEY_free(pkey);
    //RSA_free(rsa);
    RSA_free(pri_rsa);
    RSA_free(rsa_from_cert);

    return 0;
}

int main(int argc, const char* argv[]) {
    rsa_sign();
    return 1;
}
