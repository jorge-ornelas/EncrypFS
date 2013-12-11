#Initial version of the server
import sys
import time
import BaseHTTPServer
import base64
import os
from os import curdir
from os.path import join as pjoin
import crypto
import httplib, urllib, getopt

HOST_NAME = '' #TODO change this eventually to amazon host or similar.
PORT_NUMBER = 8080 # Maybe set this to 8080.
DATALOCATION = "/userdata/"
EncodeAES = lambda s: base64.b64encode(s) 
DecodeAES = lambda e: base64.b64decode(e)
SPLIT_SYMBOL = "{}{}"

class MyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_HEAD(s):
        s.send_response(200)
        s.send_header("Content-type", "text/html")
        s.end_headers()
    def do_GET(s):
        # TODO different responces to write, read, none
        # TODO verify on this end via public_key
        """Respond to a GET request."""
        s.send_response(200)
        s.send_header("Content-type", "text/html")
        s.end_headers()
        # determine the capability: write, read, or none
        name = s.path[s.path.rfind("/")+1:]
        cap = name[:name.find(":")] 
        file_name = crypto.my_hash(cap)
        abs_path = os.path.abspath(pjoin(curdir+DATALOCATION, file_name))
        if os.path.exists(abs_path):
            # it is read cap
            s.wfile.write("<html><head><title>Title goes here.</title></head>")
            s.wfile.write("<body><p>This is a test.</p>")
            s.wfile.write("<p>You accessed path: %s</p>" % s.path)
            s.wfile.write("<p>File exists: %s</p>" % pjoin(curdir+DATALOCATION, s.path))
            content = ""
            with open(abs_path, 'r') as fh:
                content =  fh.read()  
            s.wfile.write("<p>File content: data=%s</p>" % EncodeAES(content))
            s.wfile.write("</body></html>")
        else:
            file_name = crypto.my_hash(file_name)
            abs_path = os.path.abspath(pjoin(curdir+DATALOCATION, file_name))
            if os.path.exists(abs_path):
                # it is a write cap
                s.wfile.write("<html><head><title>Title goes here.</title></head>")
                s.wfile.write("<body><p>This is a test.</p>")
                s.wfile.write("<p>You accessed path: %s</p>" % s.path)
                s.wfile.write("<p>File exists: %s</p>" % pjoin(curdir+DATALOCATION, s.path))
                content = ""
                with open(abs_path, 'r') as fh:
                    content =  fh.read()  
                s.wfile.write("<p>File content: data=%s</p>" % EncodeAES(content))
                s.wfile.write("</body></html>")
            else:
                # it is nothing
                s.wfile.write("<html><head><title> ERROR </title></head>")
                s.wfile.write("<body><p>Can't access</p>")
                s.wfile.write("</body></html>")
    def do_POST(s):
        """Respond to a POST request."""
        s.send_response(200)
        s.send_header("Content-type", "text/html")
        s.end_headers()
        
        # before doing post, first check integrity, then check permissions
        # if the file exists, the path must be the write capability
        length = s.headers['content-length']
        data = s.rfile.read(int(length))
        decoded = data[5:]
        decoded = urllib.unquote(decoded).decode("utf8")
        decoded = DecodeAES(decoded)
        data_ar = decoded.split(SPLIT_SYMBOL)
        sign = data_ar[1]
        data = data_ar[0]
        # obtain public key from the data and verify
        public = data_ar[2]
         
        cap = s.path[s.path.rfind("/") + 1:].split(":")
        h = crypto.my_hash(public) 
        if h != data_ar[3] or h[:16] != cap[1]:
            send_error(s)
            return
        valid = crypto.verify_RSA(public, sign, data)
        print "Valid: ", valid 
        if not valid:
            send_error(s)
            return
        # allow write if the file does not exist or
        # when you present write cap
        file_name = crypto.my_hash(crypto.my_hash(cap[0]))
        store_path = pjoin(curdir, file_name)
        # TODO with the directory structure, notify the server of the created files
        # so that it can check if this store_path is ever created
        if os.path.exists(store_path): 
            with open(store_path, 'w') as fh:
                fh.write(decoded)
        else:
            with open(store_path, 'w') as fh:
                fh.write(decoded)
            
        # TODO support rich file format
def send_error(s):
    s.wfile.write("<html><head><title> ERROR </title></head>")
    s.wfile.write("<html><head><title> ERROR </title></head>")
    s.wfile.write("<body><p>Can't access</p>")
    s.wfile.write("</body></html>")
    s.wfile.write("<body><p>Can't access</p>")
    s.wfile.write("</body></html>")
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

