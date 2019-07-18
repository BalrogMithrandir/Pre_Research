#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>

#define MAXBUF 1024
//#define CLIENT_CERT_SUPPLY 
#define CLIENT_CERT_SUPPLY_UNMATCH
#define FLAG_FAIL_IF_NO_PEER_CERT
//#define FLAG_NONE_VERIFY_PEER
#define VERIFY_HOST
#define USER_CALLBACK

void ShowCerts(SSL * ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    
    // SSL_get_verify_result()是重点，SSL_CTX_set_verify()只是配置启不启用并没有执行认证，调用该函数才会真证进行证书认证
    // 如果验证不通过，那么程序抛出异常中止连接
    if(SSL_get_verify_result(ssl) == X509_V_OK){
        printf("证书验证通过\n");
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

int verifycallback(int preverify_ok, X509_STORE_CTX *pctx) {
    return 1;
}


int main(int argc, char **argv)
{
    int sockfd, len;
    struct sockaddr_in dest;
    char buffer[MAXBUF + 1];
    SSL_CTX *ctx;
    SSL *ssl;

    /* SSL 库初始化 */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    int (*verify_callback)(int, X509_STORE_CTX *) = NULL;
#if defined(USER_CALLBACK)
    verify_callback = &verifycallback;
#endif

    // 双向验证
    // SSL_VERIFY_PEER---要求对证书进行认证，没有证书也会放行
    // SSL_VERIFY_FAIL_IF_NO_PEER_CERT---要求客户端需要提供证书，但验证发现单独使用没有证书也会放行
#if defined(FLAG_FAIL_IF_NO_PEER_CERT)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
#elif defined(FLAG_NONE_VERIFY_PEER)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, verify_callback);
#else
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
#endif

#ifdef CLIENT_CERT_SUPPLY_UNMATCH
    std::string client_cer = "/home/caros/secure/1f7f21ff74ee4131a09135ebcc6d473d.cer";
    std::string client_key = "/home/caros/secure/1f7f21ff74ee4131a09135ebcc6d473d.key";
#else 
    std::string client_cer = "/home/caros/src/testcert/client.crt";
    std::string client_key = "/home/caros/src/testcert/client.key";
#endif
    std::string ca = "/home/caros/src/testcert/ca.crt";
    std::string cadir = "/home/caros/src/testcert/rootca";
    
    // 设置信任根证书
    if (SSL_CTX_load_verify_locations(ctx, NULL, cadir.c_str()) <= 0) {
    /*if (SSL_CTX_load_verify_locations(ctx, ca.c_str(), NULL) <= 0) {*/
        ERR_print_errors_fp(stdout);
        exit(1);
    }
#ifdef CLIENT_CERT_SUPPLY
    /* 载入用户的数字证书， 此证书用来发送给客户端。 证书里包含有公钥 */
    if (SSL_CTX_use_certificate_file(ctx, client_cer.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 载入用户私钥 */
    if (SSL_CTX_use_PrivateKey_file(ctx, client_key.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 检查用户私钥是否正确 */
    if (!SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
#endif
    /* 创建一个 socket 用于 tcp 通信 */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket");
        exit(errno);
    }
    printf("socket created\n");

    /* 初始化服务器端（对方）的地址和端口信息 */
    unsigned int server_port = 7838;
    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(server_port);
    if (inet_aton("127.0.0.1", (struct in_addr *) &dest.sin_addr.s_addr) == 0) {
        perror("127.0.0.1");
        exit(errno);
    }
    printf("address created\n");

    /* 连接服务器 */
    if (connect(sockfd, (struct sockaddr *) &dest, sizeof(dest)) != 0) {
        perror("Connect ");
        exit(errno);
    }
    printf("server connected\n");


    const char servername[] = "localhost";

    ssl = SSL_new(ctx);

#ifdef VERIFY_HOST
    /* Enable automatic hostname checks */
    if (!X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), servername, sizeof(servername) - 1)) {
        ERR_print_errors_fp(stdout);
        return 0;
    }
#endif
    SSL_set_fd(ssl, sockfd);

    /* 建立 SSL 连接 */
    if (SSL_connect(ssl) == -1)
        ERR_print_errors_fp(stderr);
    else {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);
    }

    do {
        /* 接收对方发过来的消息，最多接收 MAXBUF 个字节 */
        bzero(buffer, MAXBUF + 1);

        /* 接收服务器来的消息 */
        len = SSL_read(ssl, buffer, MAXBUF);
        if (len > 0)
            printf("接收消息成功:'%s'，共%d个字节的数据\n", buffer, len);
        else {
            printf("消息接收失败！错误代码是%d，错误信息是'%s'\n", errno, strerror(errno));
            break;
        }
        bzero(buffer, MAXBUF + 1);
        strcpy(buffer, "from client->server");
        /* 发消息给服务器 */
        len = SSL_write(ssl, buffer, strlen(buffer));
        if (len < 0) {
            printf("消息'%s'发送失败！错误代码是%d，错误信息是'%s'\n", buffer, errno, strerror(errno));
        }
        else {
            printf("消息'%s'发送成功，共发送了%d个字节！\n", buffer, len);
        }
    } while(0);

    /* 关闭连接 */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}