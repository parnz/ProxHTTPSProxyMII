#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"HTTP Proxy Tools, pyOpenSSL version"

_name = "ProxyTool"
__author__ = 'phoenix'
__version__ = '1.0'

import time
from datetime import datetime
import logging
import threading
import cgi
import socket
import select
import ssl
import http.client
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from CertTool import get_cert
from urllib.parse import urlparse

from colorama import init, Fore, Back, Style
init(autoreset=True)

logger = logging.getLogger('__main__')

message_format = """\
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
        <title>Proxy Error: %(code)d</title>
    </head>
    <body>
        <h1>%(code)d: %(message)s</h1>
        <p>The following error occurred while trying to access <strong>%(url)s</strong></p>
        <p><strong>%(explain)s</strong></p>
        <hr>Generated on %(now)s by %(server)s.
    </body>
</html>
"""

def read_write(socket1, socket2, max_idling=10):
    "Read and Write contents between 2 sockets"
    iw = [socket1, socket2]
    ow = []
    count = 0
    while True:
        count += 1
        (ins, _, exs) = select.select(iw, ow, iw, 1)
        if exs: break
        if ins:
            for reader in ins:
                writer = socket2 if reader is socket1 else socket1
                try:
                    data = reader.recv(1024)
                    if data:
                        writer.send(data)
                        count = 0
                except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
                    pass
        if count == max_idling: break

class Counter:
    reset_value = 999
    def __init__(self, start=0):
        self.lock = threading.Lock()
        self.value = start
    def increment_and_set(self, obj, attr):
        with self.lock:
            self.value = self.value + 1 if self.value < self.reset_value else 1
            setattr(obj, attr, self.value)

counter = Counter()

class ProxyRequestHandler(BaseHTTPRequestHandler):
    """RequestHandler with do_CONNECT method defined
    """
    server_version = "%s/%s" % (_name, __version__)
    # do_CONNECT() will set self.ssltunnel to override this
    ssltunnel = False
    # Override default value 'HTTP/1.0'
    protocol_version = 'HTTP/1.1'
    # To be set in each request
    reqNum = 0

    def parse_request(self):
        """Parse a request (internal).

        The request should be stored in self.raw_requestline; the results
        are in self.command, self.path, self.request_version and
        self.headers.

        Return True for success, False for failure; on failure, an
        error is sent back.

        """
        #Fix SERIOUS problem https://www.facebook.com/ai.php++++ 501(pink, Firefox) on www.facebook.com and youtube.com too
        self.command = None  # set in case of error on the first line
        self.request_version = version = self.default_request_version
        
        #print(self.request_version)
        #print(self.command)
        self.close_connection = 1
        requestline = str(self.raw_requestline, 'iso-8859-1')
        requestline = requestline.rstrip('\r\n')
        self.requestline = requestline
        
        words = requestline.split()
        #print(words)
        #if "ai.php" in words:
        
        if re.match('^(GET|POST|CONNECT|PUT|DELETE|PROPFIND|PROPATCH|PATCH|HEAD)$', words[0]):
            pass
        else:
            words[0] = re.sub('^.*?(GET|POST|CONNECT|PUT|DELETE|PROPFIND|PROPATCH|PATCH|HEAD)$', '\\1', words[0])
        #print(words[0])
        if len(words) == 3:
            command, path, version = words
            if version[:5] != 'HTTP/':
                self.send_error(400, "Bad request version (%r)" % version)
                return False
            try:
                base_version_number = version.split('/', 1)[1]
                version_number = base_version_number.split(".")
                # RFC 2145 section 3.1 says there can be only one "." and
                #   - major and minor numbers MUST be treated as
                #      separate integers;
                #   - HTTP/2.4 is a lower version than HTTP/2.13, which in
                #      turn is lower than HTTP/12.3;
                #   - Leading zeros MUST be ignored by recipients.
                if len(version_number) != 2:
                    raise ValueError
                version_number = int(version_number[0]), int(version_number[1])
            except (ValueError, IndexError):
                self.send_error(400, "Bad request version (%r)" % version)
                return False
            if version_number >= (1, 1) and self.protocol_version >= "HTTP/1.1":
                self.close_connection = 0
            if version_number >= (2, 0):
                self.send_error(505,
                          "Invalid HTTP Version (%s)" % base_version_number)
                return False
        elif len(words) == 2:
            command, path = words
            self.close_connection = 1
            if command != 'GET':
                self.send_error(400,
                                "Bad HTTP/0.9 request type (%r)" % command)
                return False
        elif not words:
            return False
        else:
            self.send_error(400, "Bad request syntax (%r)" % requestline)
            return False
        #print(command)
        self.command, self.path, self.request_version = command, path, version

        # Examine the headers and look for a Connection directive.
        try:
            self.headers = http.client.parse_headers(self.rfile,
                                                     _class=self.MessageClass)
        except http.client.LineTooLong:
            self.send_error(400, "Line too long")
            return False

        conntype = self.headers.get('Connection', "")
        if conntype.lower() == 'close':
            self.close_connection = 1
        elif (conntype.lower() == 'keep-alive' and
              self.protocol_version >= "HTTP/1.1"):
            self.close_connection = 0
        # Examine the headers and look for an Expect directive
        expect = self.headers.get('Expect', "")
        if (expect.lower() == "100-continue" and
                self.protocol_version >= "HTTP/1.1" and
                self.request_version >= "HTTP/1.1"):
            if not self.handle_expect_100():
                return False
        return True

    def do_CONNECT(self):
        "Descrypt https request and dispatch to http handler"
        # request line: CONNECT www.example.com:443 HTTP/1.1
        self.host, self.port = self.path.split(":")
        # SSL MITM
        self.wfile.write(("HTTP/1.1 200 Connection established\r\n" +
                          "Proxy-agent: %s\r\n" % self.version_string() +
                          "\r\n").encode('ascii'))
        commonname = '.' + self.host.partition('.')[-1] if self.host.count('.') >= 2 else self.host
        dummycert = get_cert(commonname)
        # set a flag for do_METHOD
        self.ssltunnel = True

        ssl_sock = ssl.wrap_socket(self.connection, keyfile=dummycert, certfile=dummycert, server_side=True)
        # Ref: Lib/socketserver.py#StreamRequestHandler.setup()
        self.connection = ssl_sock
        self.rfile = self.connection.makefile('rb', self.rbufsize)
        self.wfile = self.connection.makefile('wb', self.wbufsize)
        # dispatch to do_METHOD()
        self.handle_one_request()

    def handle_one_request(self):
        """Catch more exceptions than default

        Intend to catch exceptions on local side
        Exceptions on remote side should be handled in do_*()
        """
        try:
            BaseHTTPRequestHandler.handle_one_request(self)
            return
        except (ConnectionError, FileNotFoundError) as e:
            logger.warning("%03d " % self.reqNum + Fore.RED + "%s %s", self.server_version, e)
        except (ssl.SSLEOFError, ssl.SSLError) as e:
            if hasattr(self, 'url'):
                # Happens after the tunnel is established
                logger.warning("%03d " % self.reqNum + Fore.YELLOW + '"%s" while operating on established local SSL tunnel for [%s]' % (e, self.url))
            else:
                logger.warning("%03d " % self.reqNum + Fore.YELLOW + '"%s" while trying to establish local SSL tunnel for [%s]' % (e, self.path))
        self.close_connection = 1

    def sendout_error(self, url, code, message=None, explain=None):
        "Modified from http.server.send_error() for customized display"
        try:
            shortmsg, longmsg = self.responses[code]
        except KeyError:
            shortmsg, longmsg = '???', '???'
        if message is None:
            message = shortmsg
        if explain is None:
            explain = longmsg
        content = (message_format %
                   {'code': code, 'message': message, 'explain': explain,
                    'url': url, 'now': datetime.today(), 'server': self.server_version})
        body = content.encode('UTF-8', 'replace')
        self.send_response_only(code, message)
        self.send_header("Content-Type", self.error_content_type)
        self.send_header('Content-Length', int(len(body)))
        self.end_headers()
        if self.command != 'HEAD' and code >= 200 and code not in (204, 304):
            self.wfile.write(body)

    def deny_request(self):
        self.send_response_only(403)
        self.send_header('Content-Length', 0)
        self.end_headers()

    def redirect(self, url):
        self.send_response_only(302)
        self.send_header('Content-Length', 0)
        self.send_header('Location', url)
        self.end_headers()

    def forward_to_https_proxy(self):
        "Forward https request to upstream https proxy"
        logger.debug('Using Proxy - %s' % self.proxy)
        proxy_host, proxy_port = self.proxy.split('//')[1].split(':')
        server_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server_conn.connect((proxy_host, int(proxy_port)))
            server_conn.send(('CONNECT %s HTTP/1.1\r\n\r\n' % self.path).encode('ascii'))
            server_conn.settimeout(0.1)
            datas = b''
            while True:
                try:
                    data = server_conn.recv(4096)
                except socket.timeout:
                    break
                if data:
                    datas += data
                else:
                    break
            server_conn.setblocking(True)
            if b'200' in datas and b'established' in datas.lower():
                logger.info("%03d " % self.reqNum + Fore.CYAN + '[P] SSL Pass-Thru: https://%s/' % self.path)
                self.wfile.write(("HTTP/1.1 200 Connection established\r\n" +
                                  "Proxy-agent: %s\r\n\r\n" % self.version_string()).encode('ascii'))
                read_write(self.connection, server_conn)
            else:
                logger.warning("%03d " % self.reqNum + Fore.YELLOW + 'Proxy %s failed.', self.proxy)
                if datas:
                    logger.debug(datas)
                    self.wfile.write(datas)
        finally:
            # We don't maintain a connection reuse pool, so close the connection anyway
            server_conn.close()

    def forward_to_socks5_proxy(self):
        "Forward https request to upstream socks5 proxy"
        logger.warning(Fore.YELLOW + 'Socks5 proxy not implemented yet, please use https proxy')

    def forward_to_http_proxy(self):
        "Forward http request to upstream http proxy"
        logger.debug('Using Proxy - %s' % self.proxy)
        proxy_host, proxy_port = self.proxy.split('//')[1].split(':')
        server_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server_conn.connect((proxy_host, int(proxy_port)))
            server_conn.send(('CONNECT %s HTTP/1.1\r\n\r\n' % self.path).encode('ascii'))
            server_conn.settimeout(1.0)
            datas = b''
            while True:
                try:
                    data = server_conn.recv(4096)
                except socket.timeout:
                    break
                if data:
                    datas += data
                else:
                    break
            server_conn.setblocking(True)
            if b'200' in datas and b'established' in datas.lower():
                logger.info("%03d " % self.reqNum + Fore.CYAN + '[P] SSL Pass-Thru: https://%s/' % self.path + 'With proxy %s' % self.proxy)
                self.wfile.write(("HTTP/1.1 200 Connection established\r\n" +
                                  "Proxy-agent: %s\r\n\r\n" % self.version_string()).encode('ascii'))
                read_write(self.connection, server_conn)
            else:
                logger.warning("%03d " % self.reqNum + Fore.YELLOW + 'Proxy %s failed.', self.proxy)
                if datas:
                    logger.debug(datas)
                    self.wfile.write(datas)
        finally:
            # We don't maintain a connection reuse pool, so close the connection anyway
            server_conn.close()

    def forward_to_prox(self, prox_addr, time_out):
        "Forward http request to upstream http proxy"
        logger.debug('Using Proxy - %s' % prox_addr)
        proxy_host, proxy_port = prox_addr.split('//')[1].split(':')
        server_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server_conn.connect((proxy_host, int(proxy_port)))
            server_conn.send(('CONNECT %s HTTP/1.1\r\n\r\n' % self.path).encode('ascii'))
            server_conn.settimeout(time_out)
            datas = b''
            while True:
                try:
                    data = server_conn.recv(4096)
                except socket.timeout:
                    break
                if data:
                    datas += data
                else:
                    break
            server_conn.setblocking(True)
            if b'200' in datas and b'established' in datas.lower():
                logger.info("%03d " % self.reqNum + Fore.CYAN + '[P] SSL Pass-Thru: https://%s/ ' % self.path + 'to Privoxy')
                self.wfile.write(("HTTP/1.1 200 Connection established\r\n" +
                                  "Proxy-agent: %s\r\n\r\n" % self.version_string()).encode('ascii'))
                read_write(self.connection, server_conn)
            else:
                logger.warning("%03d " % self.reqNum + Fore.YELLOW + 'Connect to Privoxy failed.')
                if datas:
                    logger.debug(datas)
                    self.wfile.write(datas)
        finally:
            # We don't maintain a connection reuse pool, so close the connection anyway
            server_conn.close()

    def tunnel_traffic(self):
        "Tunnel traffic to remote host:port"
        logger.info("%03d " % self.reqNum + Fore.CYAN + '[D] SSL Pass-Thru: https://%s/' % self.path)
        server_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server_conn.connect((self.host, int(self.port)))
            self.wfile.write(("HTTP/1.1 200 Connection established\r\n" +
                              "Proxy-agent: %s\r\n" % self.version_string() +
                              "\r\n").encode('ascii'))
            read_write(self.connection, server_conn)
        except TimeoutError:
            self.wfile.write(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n")
            logger.warning("%03d " % self.reqNum + Fore.YELLOW + 'Timed Out: https://%s:%s/' % (self.host, self.port))
        except socket.gaierror as e:
            self.wfile.write(b"HTTP/1.1 503 Service Unavailable\r\n\r\n")
            logger.warning("%03d " % self.reqNum + Fore.YELLOW + '%s: https://%s:%s/' % (e, self.host, self.port))
        finally:
            # We don't maintain a connection reuse pool, so close the connection anyway
            server_conn.close()

    def ssl_get_response(self, conn):
        try:
            # server_conn = ssl.wrap_socket(conn, cert_reqs=ssl.CERT_REQUIRED, ca_certs="cacert.pem", ssl_version=ssl.PROTOCOL_TLSv1)
            server_conn = ssl.wrap_socket(conn, cert_reqs=ssl.CERT_NONE, ca_certs=None, ssl_version=ssl.PROTOCOL_TLSv1)
            server_conn.sendall(('%s %s HTTP/1.1\r\n' % (self.command, self.path)).encode('ascii'))
            server_conn.sendall(self.headers.as_bytes())
            if self.postdata:
                server_conn.sendall(self.postdata)
            while True:
                data = server_conn.recv(4096)
                if data:
                    self.wfile.write(data)
                else: break
        except (ssl.SSLEOFError, ssl.SSLError) as e:
            logger.error(Fore.RED + Style.BRIGHT + "[SSLError]")
            self.send_error(417, message="Exception %s" % str(e.__class__), explain=str(e))

    def purge_headers(self, headers):
        "Remove hop-by-hop headers that shouldn't pass through a Proxy"
        for name in ["Connection", "Keep-Alive", "Upgrade",
                     "Proxy-Connection", "Proxy-Authenticate"]:
            del headers[name]

    def purge_write_headers(self, headers):
        self.purge_headers(headers)
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        
    def stream_to_client(self, response):
        bufsize = 1024 * 64
        need_chunked = 'Transfer-Encoding' in response.headers
        written = 0
        while True:
            data = response.read(bufsize)
            if not data:
                if need_chunked:
                    self.wfile.write(b'0\r\n\r\n')
                break
            if need_chunked:
                self.wfile.write(('%x\r\n' % len(data)).encode('ascii'))
            self.wfile.write(data)
            if need_chunked:
                self.wfile.write(b'\r\n')
            written += len(data)
        return written
        
    def http_request_info(self):
        """Return HTTP request information in bytes
        """    
        context = ["CLIENT VALUES:",
                   "client_address = %s" % str(self.client_address),
                   "requestline = %s" % self.requestline,
                   "command = %s" % self.command,
                   "path = %s" % self.path,
                   "request_version = %s" % self.request_version,
                   "",
                   "SERVER VALUES:",
                   "server_version = %s" % self.server_version,
                   "sys_version = %s" % self.sys_version,
                   "protocol_version = %s" % self.protocol_version,
                   "",
                   "HEADER RECEIVED:"]
        for name, value in sorted(self.headers.items()):
            context.append("%s = %s" % (name, value.rstrip()))

        if self.command == "POST":
            context.append("\r\nPOST VALUES:")
            form = cgi.FieldStorage(fp=self.rfile,
                                    headers=self.headers,
                                    environ={'REQUEST_METHOD': 'POST'})
            for field in form.keys():
                fielditem = form[field]
                if fielditem.filename:
                    # The field contains an uploaded file
                    file_data = fielditem.file.read()
                    file_len = len(file_data)
                    context.append('Uploaded %s as "%s" (%d bytes)'
                                   % (field, fielditem.filename, file_len))
                else:
                    # Regular form value
                    context.append("%s = %s" % (field, fielditem.value))
                                    
        return("\r\n".join(context).encode('ascii'))

def demo():
    PORT = 8000

    class ProxyServer(ThreadingMixIn, HTTPServer):
        """Handle requests in a separate thread."""
        pass

    class RequestHandler(ProxyRequestHandler):
        "Displaying HTTP request information"
        server_version = "DemoProxy/0.1"

        def do_METHOD(self):
            "Universal method for GET, POST, HEAD, PUT and DELETE"
            message = self.http_request_info()
            self.send_response(200)
            # 'Content-Length' is important for HTTP/1.1
            self.send_header('Content-Length', len(message))
            self.end_headers()
            self.wfile.write(message)

        do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_OPTIONS = do_METHOD

    print('%s serving now, <Ctrl-C> to stop ...' % RequestHandler.server_version)
    print('Listen Addr  : localhost:%s' % PORT)
    print("-" * 10)
    server = ProxyServer(('', PORT), RequestHandler)
    server.serve_forever()


#if __name__ == '__main__':
#    try:
#        demo()
#    except KeyboardInterrupt:
#        print("Quitting...")
