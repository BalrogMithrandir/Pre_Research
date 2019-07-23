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

#define MAXBUF 1024

#define SERVER_CERT_SUPPLY
//#define SERVER_CERT_SUPPLY_UNMATCH_DOMAIN
#define FAIL_IF_NO_PEER_CERT
//#define NONE_VERIFY_PEER
//#define VERIFY_HOST
//#define USER_CALLBACK
#define USE_CA_DIR
#define JUST_ACCEPT_DET_CA

void ShowCerts(SSL * ssl)
{
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

int verify_callback_func(int preverify_ok, X509_STORE_CTX *ctx) {
    if (preverify_ok != 1) {
        ERR_print_errors_fp(stdout);
        return 0;
    }

    /*获取完整的证书链 从rootCA证书到用户证书*/
    STACK_OF(X509) *cachain = X509_STORE_CTX_get1_chain(ctx);
    if (NULL != cachain) {
        int certNum = sk_X509_num(cachain);  /*证书链深度*/

        /*使用API sk_X509_value遍历证书链时，index=0对应用户证书，index=1对应用户证书的CA证书，
        index=2对应再上一级CA证书，以此类推。index=sk_X509_num(cachain)-1 对应rootCA证书*/
        X509 *cert = sk_X509_value(cachain, 1);  /*index=1对应用户证书的CA证书*/
        if (NULL == cert) {
            return 0;
        }

        char  CN[256] = {0};
        X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, CN, sizeof(CN));
        printf("comman name: %s\n", CN);
        
        /*校验CN是否与目标域名一致：一致，返回1；不一致，返回0*/
        char expect_DN[] = "localhosttest_secondaryCA";
        if (0 == strcmp(expect_DN, CN)) {
            printf("域名匹配\n");
        } else {
            printf("域名不匹配\n");
            return 0;
        }   
    } else {
        return 0; /*没有证书信息*/
    }

    return 1;  /*返回1，ssl连接会继续建立，无论之前是否发生了错误；返回0，连接建立立即终止*/
}

int main(int argc, char **argv) {
    int sockfd, new_fd;
    socklen_t len;
    struct sockaddr_in my_addr, their_addr;
    unsigned int myport, lisnum;
    char buf[MAXBUF + 1];
    SSL_CTX *ctx;

    myport = 7838;
    lisnum = 10;

    /* SSL 库初始化 */
    SSL_library_init();

    /* 载入所有 SSL 算法 */
    OpenSSL_add_all_algorithms();

    /* 载入所有 SSL 错误消息 */
    SSL_load_error_strings();

    /* 以 SSL V2 和 V3 标准兼容方式产生一个 SSL_CTX ，即 SSL Content Text */
    /* 也可以用 SSLv2_server_method() 或 SSLv3_server_method() 单独表示 V2 或 V3标准 */
    ctx = SSL_CTX_new(SSLv23_server_method());
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
#ifdef FAIL_IF_NO_PEER_CERT
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
#elif defined(NONE_VERIFY_PEER)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, verify_callback);
#else
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
#endif

#ifdef SERVER_CERT_SUPPLY_UNMATCH_DOMAIN
    std::string server_cer = "/home/caros/src/testcert/cert/server_unmatchdomain.crt";
    std::string server_key = "/home/caros/src/testcert/cert/server_unmatchdomain.key";
#else
    std::string server_cer = "/home/caros/src/testcert/cert/server.crt";
    std::string server_key = "/home/caros/src/testcert/cert/server.key"; 
#endif
    /*std::string ca = "/home/caros/src/testcert/rootca/client_chain1.crt";*/
    std::string ca = "/home/caros/secure/root_hub.cer";
    std::string cadir = "/home/caros/src/testcert/rootca";

    // 设置信任根证书
#if defined(USE_CA_DIR)
    printf("%d\n", __LINE__);
    if (SSL_CTX_load_verify_locations(ctx, NULL, cadir.c_str()) <= 0) {
#else
    printf("%d\n", __LINE__);
    if (SSL_CTX_load_verify_locations(ctx, ca.c_str(), NULL) <= 0) {
#endif
        ERR_print_errors_fp(stdout);
        exit(1);
    }
#ifdef SERVER_CERT_SUPPLY
    /* 载入用户的数字证书， 此证书用来发送给客户端。 证书里包含有公钥 */
    if (SSL_CTX_use_certificate_file(ctx, server_cer.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 载入用户私钥 */
    if (SSL_CTX_use_PrivateKey_file(ctx, server_key.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    /* 检查用户私钥是否正确 */
    if (!SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
#endif
#if defined(JUST_ACCEPT_DET_CA)
    std::string accept_ca = "/home/caros/src/testcert/rootca/client_secondaryca1.crt";
    STACK_OF(X509_NAME) *accept_CA_stack = SSL_load_client_CA_file(accept_ca.c_str());
    if (NULL == accept_CA_stack) {
        printf("get accept_CA_stack fialed\n");
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    SSL_CTX_set_client_CA_list(ctx, accept_CA_stack);
#endif

    /* 开启一个 socket 监听 */
    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    } else {
        printf("socket created\n");
    }

    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = PF_INET;
    my_addr.sin_port = htons(myport);
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

#ifdef VERIFY_HOST
        /* Enable automatic hostname checks */
        const char clientname[] = "localhost";
        if (!X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), clientname, sizeof(clientname) - 1)) {
            ERR_print_errors_fp(stdout);
            return 0;
        }
#endif

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