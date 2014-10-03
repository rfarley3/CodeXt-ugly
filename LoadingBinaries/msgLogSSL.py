#!/usr/bin/env python
#https://docs.python.org/dev/library/ssl.html
#http://stackoverflow.com/questions/15820634/tls-echo-server-and-echoclient-in-python-crashes
import socket, ssl


def server():
    bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsocket.bind(('127.0.0.1', 10000))
    bindsocket.listen(5)

    print "Listening"
    tls_serv = ssl.wrap_socket(bindsocket, server_side=True, keyfile='./my.key', certfile="./my.crt", ssl_version=ssl.PROTOCOL_TLSv1)
    connstream, fromaddr = tls_serv.accept()
    #connstream = ssl.wrap_socket(newsocket, server_side=True, certfile="my.crt", ssl_version=ssl.PROTOCOL_TLSv1)
    print "Connected"
    try:
        deal_with_client(connstream)
    finally:
        connstream.shutdown(socket.SHUT_RDWR)
        connstream.close()
    bindsocket.shutdown(socket.SHUT_RDWR)
    bindsocket.close()
        

def deal_with_client(s):
    data = "ddfd"
    # empty data means the client is finished with us
    while len (data) > 0:
        print "Ready to recv"
        data = s.recv(1024)
        print "Recv'd: " + data
    	send_data = "Msg of %uB recv'd and logged, secret: 0xcafebabe\n"% len (data)
        s.send (send_data)
        print "Ready to recv"
        data = s.recv(1024)
        print "Attack string, " + str (len (data) ) + "B: " + ''.join(format(x, '02x') for x in bytearray(data) )
        print "Recv'd"
        data = ""
        


server ()
"""
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout my.key -out my.crt
Generating a 2048 bit RSA private key
..........................+++
............................................+++
writing new private key to 'my.key'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:US
State or Province Name (full name) [Some-State]:VA
Locality Name (eg, city) []:Fairfax
Organization Name (eg, company) [Internet Widgits Pty Ltd]:GMU
Organizational Unit Name (eg, section) []:NSSL
Common Name (eg, YOUR name) []:Farley
Email Address []:
"""