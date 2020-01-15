import os, sys, socket, ssl, time

bindsocket = socket.socket()
print( "socket create success" )
bindsocket.bind(('127.0.0.1', 10023))
print( "socket bind success" )
bindsocket.listen(5)
print( "socket listen success" )

def do_something(connstream, data):
    print("data length:",len(data))
    return True
 
def deal_with_client(connstream):
    t_recv=0
    t_send=0
    n = 0
    t1=time.clock()
    data = connstream.recv(1024)
    t2=time.clock()
    print("receive time:",t2-t1)
    # empty data means the client is finished with us
    while data:
        if not do_something(connstream, data):
            # we'll assume do_something returns False
            # when we're finished with client
            break
        n = n + 1
        t1=time.clock()
        connstream.send(b'b'*1024)
        t2=time.clock()
        t_send += t2-t1
        print("send time:",t2-t1)
        t1=time.clock()
        data = connstream.recv(1024)
        t2=time.clock()
        t_recv +=t2-t1
        print("receive time:",t2-t1)
    print("avg send time:",t_send/n,"avg receive time:",t_recv/n)
    # finished with client
 
while True:
    newsocket, fromaddr = bindsocket.accept()
    print( "socket accept one client" )
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

    cacert = "../../testcert/newroot_by_hanchangqing/iot-idg-ca.cer" 
    cer_file = "../../testcert/server.cer"
    key_file = "../../testcert/server.key"
    
#    pipe_file = "/tmp/file"
#    pipeout = os.open(pipe_file, os.O_RDONLY)

#    s = os.read(pipeout, 10000)
    ssl_ctx.load_cert_chain(cer_file, key_file) 
    ssl_ctx.load_verify_locations(cacert, "../../testcert/newroot_by_hanchangqing/")
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED
    connstream = ssl_ctx.wrap_socket(newsocket, server_side=True)
    try:
        deal_with_client(connstream)
    finally:
        connstream.shutdown(socket.SHUT_RDWR)
        connstream.close()

