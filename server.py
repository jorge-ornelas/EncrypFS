#Initial version of the server
import sys
import time
import BaseHTTPServer
import os
from os import curdir
from os.path import join as pjoin

HOST_NAME = '127.0.0.1' #TODO change this eventually to amazon host or similar.
PORT_NUMBER = 8000 # Maybe set this to 8080.

class MyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_HEAD(s):
        s.send_response(200)
        s.send_header("Content-type", "text/html")
        s.end_headers()
    def do_GET(s):
        """Respond to a GET request."""
        s.send_response(200)
        s.send_header("Content-type", "text/html")
        s.end_headers()
        s.wfile.write("<html><head><title>Title goes here.</title></head>")
        s.wfile.write("<body><p>This is a test.</p>")
        s.wfile.write("<p>You accessed path: %s</p>" % s.path)
        file_name = s.path[s.path.rfind("/") + 1:]
        abs_path = os.path.abspath(pjoin(curdir, file_name))
        if os.path.exists(abs_path):
            s.wfile.write("<p>File exists: %s</p>" % pjoin(curdir, s.path))
            content = ""
            with open(abs_path, 'r') as fh:
                content =  fh.read()  
            s.wfile.write("<p>File content: %s</p>" % content)
        s.wfile.write("</body></html>")
    def do_POST(s):
        """Respond to a POST request."""
        if s.path.endswith(".txt"):
            file_name = s.path[s.path.rfind("/") + 1:]
            store_path = pjoin(curdir, file_name)
            
            s.wfile.write('Client: %s\n' % str(s.client_address))
            s.wfile.write('Path: %s\n' % s.path)
            length = s.headers['content-length']
            data = s.rfile.read(int(length))

            with open(store_path, 'w') as fh:
                fh.write(data.decode())
            
            s.send_response(200)
            s.send_header("Content-type", "text/html")
            s.end_headers()
        else:
            # Accept txt file for now. 
            # TODO support rich file format
            s.send_response(304)

if __name__ == '__main__':
    server_class = BaseHTTPServer.HTTPServer
    httpd = server_class((HOST_NAME, PORT_NUMBER), MyHandler)
    print time.asctime(), "Server Starts - %s:%s" % (HOST_NAME, PORT_NUMBER)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print time.asctime(), "Server Stops - %s:%s" % (HOST_NAME, PORT_NUMBER)
