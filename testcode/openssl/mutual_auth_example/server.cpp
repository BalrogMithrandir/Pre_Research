#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include "cfg.h"
#include "base.h"

#define MAXBUF 1024

#define USER_CALLBACK

int verify_callback_func(int preverify_ok, X509_STORE_CTX *ctx) {
//    printf("verfiy cb, preverify_ok is %d\n", preverify_ok);
    if (preverify_ok != 1) {
        printf("verify cb failed for pre verify\n");
        return 0;
    }

    //可选：检查客户端的CA证书的CN或其他扩展字段
    int depth = X509_STORE_CTX_get_error_depth(ctx);
    if (depth != 1) {
        return preverify_ok;
    }

    preverify_ok = check_cert_cn(ctx, ACCEPT_CLIENT_CA_CN);    

    /*返回1，ssl连接会继续建立，无论之前是否发生了错误；返回0，连接建立立即终止*/ 
    return preverify_ok;  
}

int main(int argc, char **argv) {
    int sockfd, new_fd;
    socklen_t len;
    struct sockaddr_in my_addr, their_addr;
    unsigned int lisnum = 10;
    char buf[MAXBUF + 1];

    /* SSL 库初始化 */
    SSL_library_init();

    /* 载入所有 SSL 算法 */
    OpenSSL_add_all_algorithms();

    /* 载入所有 SSL 错误消息 */
    SSL_load_error_strings();

    /* 以 SSL V2 和 V3 标准兼容方式产生一个 SSL_CTX ，即 SSL Content Text */
    /* 也可以用 SSLv2_server_method() 或 SSLv3_server_method() 单独表示 V2 或 V3标准 */
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    
    int (*verify_callback)(int, X509_STORE_CTX *) = NULL;
#if defined(USER_CALLBACK)
    verify_callback = &verify_callback_func;
#endif

    // 双向认证
    // SSL_VERIFY_PEER---配置openssl对证书进行认证，证书不匹配会报错，但是没有证书不会报错
    // SSL_VERIFY_FAIL_IF_NO_PEER_CERT---强制要求客户端需要提供证书
    // SSL_VERIFY_NONE---不对对端证书进行验证，即使对端证书不合法，连接依然可以建立
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);

    if (1 != init_cert_key_ca(ctx, SERVER_CERT, SERVER_KEY, CLIENT_CA)) {
        printf("init cert key or ca failed\n");
        exit(1);
    }

    //通过非回调函数的方式限定客户端证书的CA证书
    set_accept_client_ca(ctx, "../cert/ca.crt");

    /* 开启一个 socket 监听 */
    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    } else {
        printf("socket created\n");
    }

    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = PF_INET;
    my_addr.sin_port = htons(SERVER_PORT);
    my_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr *) &my_addr, sizeof(struct sockaddr))
            == -1) {
        perror("bind");
        exit(1);
    } else {
        printf("binded\n");
    }

    if (listen(sockfd, lisnum) == -1) {
        perror("listen");
        exit(1);
    } else {
        printf("begin listen\n");
    }

    while (1) {
        SSL *ssl;
        len = sizeof(struct sockaddr);

        /* 等待客户端连上来 */
        if (-1 == (new_fd = accept(sockfd, (struct sockaddr *) &their_addr, &len))) {
            perror("accept");
            exit(errno);
        } else {
            printf("server: got connection from %s, port %d, socket %d\n",
                    inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port),
                    new_fd);
        }

        /* 基于 ctx 产生一个新的 SSL */
        ssl = SSL_new(ctx);

        /*可选：检查客户端证书的CN*/
        if (1 != set_accept_client_cn(ssl, CLIENT_CN)) {
            return 1;
        }
        
        /* 将连接用户的 socket 加入到 SSL */
        SSL_set_fd(ssl, new_fd);

        /* 建立 SSL 连接 */
        if (SSL_accept(ssl) == -1) {
            perror("ssl accept");
            ERR_print_errors_fp(stdout);
            close(new_fd);
            break;
        }
        ShowCerts(ssl);

        do {
            /* 开始处理每个新连接上的数据收发 */
            bzero(buf, MAXBUF + 1);
            strcpy(buf, "server->client");

            /* 发消息给客户端 */
            len = SSL_write(ssl, buf, strlen(buf));
            if (len <= 0) {
                printf("消息'%s'发送失败！错误代码是%d，错误信息是'%s'\n", buf, errno,
                        strerror(errno));
                break;
            } else {
                printf("消息'%s'发送成功，共发送了%d个字节！\n", buf, len);
            }

            bzero(buf, MAXBUF + 1);

            /* 接收客户端的消息 */
            len = SSL_read(ssl, buf, MAXBUF);
            if (len > 0) {
                printf("接收消息成功:'%s'，共%d个字节的数据\n", buf, len);
            }
            else {
                printf("消息接收失败！错误代码是%d，错误信息是'%s'\n",
                errno, strerror(errno));
            }
        } while(0);

        /* 处理每个新连接上的数据收发结束 */
        /* 关闭 SSL 连接 */
        SSL_shutdown(ssl);

        /* 释放 SSL */
        SSL_free(ssl);
        
        /* 关闭 socket */
        close(new_fd);
    }

    /* 关闭监听的 socket */
    close(sockfd);
    
    /* 释放 CTX */
    SSL_CTX_free(ctx);
    
    return 0;
}
