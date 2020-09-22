import os, sys, socket, ssl, pprint,time, stat

start=time.time()
cnt=0
while True: 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # require a certificate from the server

    capath = "../testcert/otawebsrv_root.pem"
    certpath = "../testcert/vin.cer"
    keypath = "../testcert/vin.key"

    ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_ctx.check_hostname = False

    ssl_ctx.load_cert_chain(certpath, keypath)
    ssl_ctx.load_verify_locations(capath)
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED
    ssl_sock = ssl_ctx.wrap_socket(s)
    
    ssl_sock.connect(('127.0.0.1', 10023))
    
    cnt=cnt+1
    #print(len(data))

    #pprint.pprint(ssl_sock.getpeercert())
    # note that closing the SSLSocket will also close the underlying socket
    n=0
    t_send=0
    t_recv=0
    
    n = n+1
    t1=time.clock()
    ssl_sock.send(b'a'*100)
    t2=time.clock()
    t_send += t2-t1 
    t1=time.clock()
    data=ssl_sock.recv(1024)
    t2=time.clock()
    t_recv += t2-t1
    #ssl_sock.send(b'')
    ssl_sock.close()

    end=time.time()
    past=end-start
    if past > 60:
        print "cnt is ", cnt
        break

