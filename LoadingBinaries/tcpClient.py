#!/usr/bin/env python

import socket

TCP_IP = '127.0.0.1'
TCP_PORT = 10000
BUFFER_SIZE = 1024
INIT_MESSAGE = "Are you there?\n"
 
 
s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
s.connect ((TCP_IP, TCP_PORT))
s.send (INIT_MESSAGE)
print "Sent: " + INIT_MESSAGE
data = s.recv (BUFFER_SIZE)
#data = "ffa4a36c\n"
print "Recv'd: " + data
s.close()
