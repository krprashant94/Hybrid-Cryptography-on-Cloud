import socket
import os

# Standard socket stuff:
host = ''
port = 8080
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((host, port))
sock.listen(5) 

# Loop forever, listening for requests:
while True:
    csock, caddr = sock.accept()
    print("Connection from: " + str(caddr))
    req = csock.recv(1024)  # get the request, 1kB max
    print(req)
    # Look in the first line of the request for a move command
    # A move command should be e.g. 'http://server/move?a=90'
    filename = 'static/index.html'
    f = open(filename, 'r')

    csock.sendall(str.encode("HTTP/1.0 200 OK\n",'iso-8859-1'))
    csock.sendall(str.encode('Content-Type: text/html\n', 'iso-8859-1'))
    csock.send(str.encode('\r\n'))
    # send data per line
    for l in f.readlines():
        # print('Sent ', repr(l))
        csock.sendall(str.encode(""+l+"", 'iso-8859-1'))
        l = f.read(1024)
    f.close()

    csock.close()