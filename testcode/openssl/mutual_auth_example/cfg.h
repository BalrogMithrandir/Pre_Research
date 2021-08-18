#pragma once

#define LOAD_FROM_MEMORY
//#define LOAD_FROM_FILE

#define SERVER_PORT 7854

#define SERVER_IP           "127.0.0.1"

//期望的server证书中的CN字段，一般为server的ip或者域名
#define SERVER_CN           "127.0.0.1"

//期望的客户端的证书的域名
#define CLIENT_CN           "test_client"

//期望的客户端CA的证书的域名
#define ACCEPT_CLIENT_CA_CN "RootCA"

#define ACCEPT_CLIENT_CA "../cert/ca.crt"

#define SERVER_CERT "../cert/server.crt"
#define SERVER_KEY  "../cert/server.key"
#define SERVER_CA   "../cert/ca.crt"

#define CLIENT_CERT "../cert/client.crt"
#define CLIENT_KEY  "../cert/client.key"
#define CLIENT_CA   "../cert/ca.crt"

#define MAXBUF 1024
