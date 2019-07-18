import sys, socket, ssl, pprint,time
sys.path.append('/home/caros/secure_upgrade/python')
try:
    import secksproxy_export
except ImportError:
    print 'Warning: secksproxy_export import fail'
start=time.time()
cnt=0
while True: 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', 10024))

    # note that closing the SSLSocket will also close the underlying socket
    n=0
    t_send=0
    t_recv=0
    n = n+1
    t1=time.clock()
    s.send(b'a'*100)
    t2=time.clock()
    t_send += t2-t1 
    t1=time.clock()
    data=s.recv(1024)
    t2=time.clock()
    t_recv += t2-t1
    cnt=cnt+1
    #print(len(data))
    end=time.time()
    past=end-start
    if past > 60:
        print "cnt is ", cnt
        break
print("avg send time:",t_send/n,"avg receive time:",t_recv/n)
#s.send(b'')
s.close()

