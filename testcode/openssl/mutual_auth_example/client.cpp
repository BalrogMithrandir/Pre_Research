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

#include "cfg.h"
#include "base.h"

#define USER_CALLBACK

int verify_callback_func(int preverify_ok, X509_STORE_CTX *ctx) {
//    printf("verfiy cb, preverify_ok is %d\n", preverify_ok);
    if (preverify_ok != 1) {
        printf("verify cb failed for pre verify\n");
        return 0;
    }
    
    int depth = X509_STORE_CTX_get_error_depth(ctx);
    if (depth != 0) {
        return preverify_ok;
    }
    
    preverify_ok = check_cert_cn(ctx, SERVER_CN);
    
    /*返回1，ssl连接会继续建立，无论之前是否发生了错误；返回0，连接建立立即终止*/ 
    return preverify_ok;  
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
    verify_callback = &verify_callback_func;
#endif

    // 单向认证
    // SSL_VERIFY_PEER---配置openssl对证书进行认证，证书不匹配会报错，但是没有证书不会报错
    // SSL_VERIFY_NONE---不对对端证书进行验证，即使对端证书不合法，连接依然可以建立
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

    if (1 != init_cert_key_ca(ctx, CLIENT_CERT, CLIENT_KEY, SERVER_CA)) {
        printf("init cert key or ca failed\n");
        exit(1);
    }
 
    /* 创建一个 socket 用于 tcp 通信 */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket");
        exit(errno);
    }
    printf("socket created\n");

    /* 初始化服务器端（对方）的地址和端口信息 */
    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(SERVER_PORT);
    if (inet_aton(SERVER_IP, (struct in_addr *) &dest.sin_addr.s_addr) == 0) {
        exit(errno);
    }
    printf("address created\n");

    /* 连接服务器 */
    if (connect(sockfd, (struct sockaddr *) &dest, sizeof(dest)) != 0) {
        perror("Connect ");
        exit(errno);
    }
    printf("server connected\n");

    ssl = SSL_new(ctx);

    /*校验服务端证书的域名信息：可以通过回调函数，也可以在这儿设置*/
    if (!X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), SERVER_IP, strlen(SERVER_IP))) {
        ERR_print_errors_fp(stdout);
        return 0;
    }

    if (!X509_VERIFY_PARAM_set_purpose(SSL_get0_param(ssl), 1)) {
         ERR_print_errors_fp(stdout);
         return 0;
    }
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
