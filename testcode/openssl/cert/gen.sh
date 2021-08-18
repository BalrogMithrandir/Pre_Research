#!/bin/bash
str="/C=CN/ST=Beijing/L=HaiDian/O=Baidu/OU=IVI/CN=RootCA"
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -subj $str -days 5000 -out ca.crt 

str="/C=CN/ST=Beijing/L=HaiDian/O=Baidu/OU=IVI/CN=127.0.0.1"
openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj $str -out server.csr 
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 5000

str="/C=CN/ST=Beijing/L=HaiDian/O=Baidu/OU=IVI/CN=test_client"
openssl genrsa -out client.key 2048
openssl req -new -key client.key -subj $str -out client.csr 
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 5000
