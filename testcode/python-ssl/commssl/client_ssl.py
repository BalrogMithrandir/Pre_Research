import os, sys, socket, ssl, pprint,time, stat
sys.path.append('/home/caros/secure_upgrade/python')
try:
    import secksproxy_export
except ImportError:
    print 'Warning: secksproxy_export import fail'
start=time.time()
cnt=0
while True: 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # require a certificate from the server
    # capath = "/home/caros/src/python-ssl-test/cert/second-ca.crt"
    capath = "/home/caros/secure/otawebsrv_root.pem"
    alias = 'ota'
    ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_ctx.check_hostname = False
    cert = secksproxy_export.export_proxy(1, 0, alias)
    key = secksproxy_export.export_proxy(0, 0, alias)
    
    tmpcertpath = "./tmpcert.cer"
    certfile = open(tmpcertpath, 'w')
    certfile.write(cert[0])
    
    tmpkeypath = "./tmpkey.key"
    keyfile = open(tmpkeypath, 'w')
    keyfile.write(key[0])

    certfile.close()
    keyfile.close()

    ssl_ctx.load_cert_chain(tmpcertpath, tmpkeypath)
    ssl_ctx.load_verify_locations(capath)
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED
    ssl_sock = ssl_ctx.wrap_socket(s)
    os.remove(tmpcertpath)
    os.remove(tmpkeypath)
    
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

