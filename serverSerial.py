#!/usr/bin/env python
# Rafael Aroca <aroca@ufscar.br>

# WebSocket to Python Interactive Console
# Part of BIPES Project - Block based Integrated Platform for Embedded Systems
# http://www.bipes.net.br

# Based on PyWSocket by Sanket
# https://superuser.blog/websocket-server-python/
# https://tools.ietf.org/id/draft-ietf-hybi-thewebsocketprotocol-09.html
# https://github.com/sanketplus/PyWSocket

# Based also on socketserverREPL by Ivor Wanders
# https://github.com/iwanders/socketserverREPL

# WebSocket Protocol
# https://tools.ietf.org/html/rfc6455

import logging
import code
import threading
import sys
import time
import socket
import argparse
import os
import sys
# import readline # optional, will allow Up/Down/History in the console


# For Python WebREPL
import hashlib
import base64
WS_MAGIC_STRING = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

logging.basicConfig(format='%(message)s')

global line
line = ""
global pasteMode
pasteMode = False
global pasteModeEnded
pasteModeEnded = False


def ByteToHex(byteStr):
    """
    Convert a byte string to it's hex string representation e.g. for output.
    """

    # Uses list comprehension which is a fractionally faster implementation than
    # the alternative, more readable, implementation below
    #
    #    hex = []
    #    for aChar in byteStr:
    #        hex.append( "%02X " % ord( aChar ) )
    #
    #    return ''.join( hex ).strip()

    return ''.join(["%02X " % ord(x) for x in byteStr]).strip()


# load following in python2 and python3 compatible way.
if sys.version_info.major == 2:
    import SocketServer as ss
else:
    import socketserver as ss

# Create a function that is available from the shell to gracefully exit server
# after disconnect.
should_exit = False

global auth
auth = 0


def halt():
    global should_exit
    print("Shutting down after all clients disconnect.")
    should_exit = True


thread_scope = threading.local()
original_stdout = sys.stdout


class ThreadAwareStdout(object):
    """
        This class acts as a file object and based on the thread it is used
        from it uses to the appropriate stream. If it is called from the main
        thread "wfile" will not be present and it will write to the original
        stdou, which is the stdout of the server process.
    """

    def write(self, data):
        if hasattr(thread_scope, "wfile"):

            # original way of sending - using raw socket
            # wont work for websocket!
            # thread_scope.wfile.write(data.encode('ascii'))

            # Send using WebSocket
            data = data.replace("\n", "\n\r")
            total = len(data)
            # logging.warning(total)
            #logging.warning("Bytes to send = " + str(total))
            sent = 0

            while sent < total:
                #logging.warning("loop: sent = " + str(sent))
                #logging.warning("loop: total = " + str(total))
                #ogging.warning("stdout sending: " + data)
                dataL = data[sent:sent+100]
                #dataL = dataL + '\r\n'
                #dataL = '\r\n' + dataL
                #dataL.replace(r"\n", r"\n\r")
                #rame = [129]
                #frame += [len(dataL)]
                #frame_to_send = bytearray(frame) + dataL

                try:
                    bytearr = [0x81, len(dataL)]
                    bytearr.extend(dataL.encode('ascii'))
                    thread_scope.wfile.write(bytearray(bytearr))
                    # thread_scope.wfile.write(dataL.encode('ascii'))
                    thread_scope.wfile.flush()
                except Exception as e:
                    emsg = sys.exc_value
                    logging.warning(
                        "stdout send: exception while writing to socket: " + str(emsg))
                    pass
                sent = sent + 100
            #logging.warning("stdout write done")

        else:
            try:
                original_stdout.write(data.encode('ascii'))
            except:
                pass

    def flush(self):
        if hasattr(thread_scope, "wfile"):
            thread_scope.wfile.flush()
        else:
            original_stdout.flush()


sys.stdout = ThreadAwareStdout()
sys.stderr = ThreadAwareStdout()

# Relevant links:
# https://docs.python.org/2/library/code.html
# https://github.com/python/cpython/blob/2.7/Lib/code.py


class InteractiveSocket(code.InteractiveConsole):
    def __init__(self, rfile, wfile, locals=None):
        """
            This class actually creates the interactive session and ties it
            to the socket by reading input from the socket and writing output.

            This class is always located in the thread that is created per
            connection.
        """
        code.InteractiveConsole.__init__(self, locals)
        self.rfile = rfile
        self.wfile = wfile

        # print("Use Print() to print on the server thread, use halt() to close"
        #      " the server after the last session terminates.")

    def write(self, data):
        # Write data to the stream.

        if not self.wfile.closed:
            #data = data.replace("\r", "\n\r\n")
            data = data.replace("\n", "\r\n")
            total = len(data)
            # logging.warning(total)
            #logging.warning("Bytes to send = " + str(total))
            sent = 0

            while sent < total:
                #logging.warning("loop: sent = " + str(sent))
                #logging.warning("loop: total = " + str(total))
                #logging.warning("stderr sending: " + data)
                dataL = data[sent:sent+100]
                #dataL = dataL + '\r\n'
                #dataL.replace(r"\n", r"\n\r")
                #rame = [129]
                #frame += [len(dataL)]
                #frame_to_send = bytearray(frame) + dataL

                try:
                    bytearr = [0x81, len(dataL)]
                    bytearr.extend(dataL.encode('ascii'))
                    self.wfile.write(bytearray(bytearr))
                    # self.wfile.write(dataL.encode('ascii'))
                    self.wfile.flush()
                except Exception as e:
                    emsg = sys.exc_value
                    logging.warning(
                        "stdout send: exception while writing to socket: " + str(emsg))
                    pass
                sent = sent + 100
            #logging.warning("stderr write done")

    def raw_input(self, prompt=""):
        # Try to read data from the stream.
        if (self.wfile.closed):
            raise EOFError("Socket closed.")

        # logging.warning('6')

        # print the prompt.
        logging.warning('========>>>>>>>>> prompt = ' + prompt)
        self.write(prompt)

        while True:

            # Process the input.
            payload_len = 0
            try:
                #raw_value = self.rfile.readline()
                raw_value = self.rfile.read(7)
                #raw_value = self.rfile.read(7)
                # for i in raw_value:
                #    logging.warning('raw_value' + str(i) + ' = : ' + hex(raw_value[i]))
            except:
                logging.warning('except on read')
                pass

            try:
                x = bytes(raw_value)
                y = ByteToHex(x)

                #payload_len = x[2] - 128
                #logging.warning('Received = ' + y)
                #logging.warning('opcode1 =  ' + ByteToHex(x[0]))
                #logging.warning('len =  ' + ByteToHex(x[1]))
                #logging.warning('len = ' + ByteToHex(x[2]))
                #logging.warning('len = ' + payload_len)
            except:
                logging.warning('except on len(raw_value)')
                pass

            try:
                t = int(ByteToHex(x[0]), 16)
                l = int(ByteToHex(x[1]), 16)

                if t == 0x88:
                    logging.warning('Received a close socket packet')
                    pass

                # if l & 0x80: # len is composed of 7 LSBs, so we excludde MSB
                if l & 0x80 and t == 0x81:  # len is composed of 7 LSBs, so we excludde MSB
                    #logging.warning('Masked message')
                    l = l & 127
                    #logging.warning('payload_len = ' + str(l))
                    if l > 1:
                        #logging.warning('payload_len >1, getting more data')
                        raw_value = self.rfile.read(l-1)
                        x2 = bytes(raw_value)
                        y = ByteToHex(x2)
                        #logging.warning('Received2 = ' + y)

                    if l > 126:
                        logging.warning(
                            'TODO: must implement handle for frame > 127 byes')
                        pass
                    # mask
                    m1 = int(ByteToHex(x[2]), 16)
                    m2 = int(ByteToHex(x[3]), 16)
                    m3 = int(ByteToHex(x[4]), 16)
                    m4 = int(ByteToHex(x[5]), 16)
                    data = int(ByteToHex(x[6]), 16)
                    #logging.warning('MASK: ' + str(m1) + ' ' + str(m2) + ' ' + str(m3))
                    #logging.warning('Data: ' + str(data))

                    mask = bytearray(4)
                    frame = bytearray(6+l)
                    #frame = bytearray(7)
                    mask[0] = m1
                    mask[1] = m2
                    mask[2] = m3
                    mask[3] = m4

                    frame[0] = t
                    frame[1] = l
                    frame[2] = m1
                    frame[3] = m2
                    frame[4] = m3
                    frame[5] = m4
                    frame[6] = data

                    if (l > 1):
                        for i in range(0, l-1):
                            data2 = int(ByteToHex(x2[i]), 16)
                            frame[7+i] = data2

                    #logging.warning('Frame remontado')
                    encrypted_payload = frame[6: 6+l]
                    payload = bytearray(
                        [encrypted_payload[i] ^ mask[i % 4] for i in range(l)])
                    #logging.warning('Decoded payload = ' + str(payload))

                if t == 0x81:
                    #logging.warning('Text WebSocket packet')
                    logging.warning('')
                    #k = int(ByteToHex(x[2]), 16)
                    #payload_len = k - 128
                    #logging.warning('k = ' + str(k))
                    #logging.warning('payload_len = ' + str(payload_len))
            except:
                logging.warning('except on decode')
                pass

            # here, we have to build the whole line and just send after a full line
            # is written
            global line
            # logging.warning('-------------------')
            #logging.warning('line before = ' + str(line))
            #logging.warning('payload before = ' + str(payload))

            x = bytes(payload)
            p0 = int(ByteToHex(x[0]), 16)

            #logging.warning('data = ' + str(data))
            # 0x04 and 0x05 are for raw transmission mode
            if p0 == 0x04 or p0 == 0x05:
                logging.warning('will remove 0x05 and 0x04')
                payload = payload[1:]
            if p0 == 0x04 or p0 == 0x05:
                logging.warning('will remove 0x05 and 0x04 again')
                payload = payload[1:]

            payload = payload.decode("utf8", "ignore")
            logging.warning('payload depois = ' + str(payload))
            line = line + payload
            #logging.warning('line = ' + line)

            global pasteMode
            global pasteModeEnded
            if p0 == 0x05:  # start paste mode
                logging.warning('PASTE MODE STARTED')
                line = ''
                pasteMode = True
                pasteModeEnded = False

            if p0 == 0x04:  # end paste mode
                logging.warning('PASTE MODE ENDED')
                logging.warning('==============')
                newline = ''
                for c in line:
                    ch = int(ByteToHex(c), 16)
                    logging.warning("C: " + str(c) + " CH: " + str(ch))
                    if ch == 13:
                        newline = newline + '\r\n'
                    else:
                        newline = newline + c

                logging.warning('==============')
                logging.warning(newline)
                line = newline
                logging.warning('==============')
                pasteMode = False
                pasteModeEnded = True
                # runsource(line)

                logging.warning('Trying to exec code all at once')
                self.write(line)
                exec(line, globals())

            y = ByteToHex(x)
            logging.warning('payload = ' + y)

            # Check if we got a backspace and send correct pattern
            if y == '7F':  # backspace received
                # backspace to remote terminal is 1b 5b 4b
                logging.warning('backspace')
                #bytearr = [ 0x81, 0x01, 0x08, 0x81, 0x03, 0x1b, 0x5b, 0x4b]
                #bytearr = [ 0x81, 0x01, 0x08, 0x81, 0x03, 0x1b, 0x5b, 0x4b]
                self.write(b'\x08')
                self.write(b'\x1b')
                self.write(b'\x5b')
                self.write(b'\x4b')

                # remove character from input string to python
                logging.warning("line before backspace = " + line)
                line = line[:-2]
                logging.warning("line after backspace = " + line)

            elif y == "1B 5B 41":
                logging.warning("UP Key pressed ")
            elif y == "1B 5B 42":
                logging.warning("DOWN Key pressed ")

            else:
                # echo character back to client, for better interactive session
                # echo typed character back to WebREPL client
                # self.write(".") #Test / Works!
                if not pasteMode:
                    self.write(x)

            logging.warning('prompt = ' + prompt)

            if not pasteMode and (y == '0D' or '0D' in y) or pasteModeEnded:
                pasteModeEnded = False

                #logging.warning(' ')
                logging.warning('line = ' + line)
                x = bytes(line)
                y = ByteToHex(x)
                logging.warning('lineBytes = ' + y)
                #logging.warning(' ')

                logging.warning('ENTER PRESSED ')
                self.write("\r\n")
                #r = line

                # isso resolveu parcialmente, mas agora temos
                # outro bug!
                logging.warning('prompt = ' + prompt)
                if prompt.strip() == '...':
                    logging.warning('Prompt with ... ')
                    logging.warning('len(line) =' + str(len(line)))
                    if len(line) == 1:
                        r = line
                    else:
                        r = line.rstrip()
                else:
                    logging.warning('Prompt with >>> ')
                    r = line

                # try:
                    # Python 2 / 3 difference.
                    #r = r.decode('ascii')
                    #r = "i=10 \r\n"
                    #logging.warning('8: ' + r)
                # except:
                #    logging.warning('except on 8' + r)
                #    pass

                # The default repl quits on control+d, control+d causes the line that
                # has been typed so far to be sent by netcat. That means that pressing
                # control+D without anything having been typed in results in a ''
                # to be read into raw_value.
                # But when '' is read we know control+d has been sent, we raise
                # EOFError to gracefully close the connection.
                if (len(r) == 0):
                    raise EOFError(
                        "Empty line, disconnect requested with control-D.")

                #global line
                line = ''
                return r


class RequestPythonREPL(ss.StreamRequestHandler):
    """
        THis is the entry point for connections from the socketserver.
    """

    def handle(self):
        # Actually handle the request from socketserver, every connection is
        # handled in a different thread.

        print("New connection")

        # Create a new Print() function that outputs to the original stdout.
        def Print(f):
            f = str(f)
            try:
                f = bytes(f, 'ascii')
            except:
                pass
            original_stdout.write(f.decode('ascii'))
            original_stdout.write("\n")
            original_stdout.flush()

        # self.request is the TCP socket connected to the client
        self.data = self.request.recv(1024).strip()
        headers = self.data.split("\r\n")

        # is it a websocket request?
        if "Connection: Upgrade" in self.data and "Upgrade: websocket" in self.data:
            # getting the websocket key out
            for h in headers:
                if "Sec-WebSocket-Key" in h:
                    key = h.split(" ")[1]
        # let's shake hands shall we?
            self.shake_hand(key)

            self.send_frame(
                "\r\nWelcome to BIPES Project. Type s to start python shell ...\r\n")
            # TODO: ask for password

            global auth
            auth = 0
            while auth == 0:
                try:
                    payload = self.decode_frame(
                        bytearray(self.request.recv(1024).strip()))
                    decoded_payload = payload.decode('utf-8')
                    # print "R: = " + decoded_payload
                except:
                    pass

                if "s" == decoded_payload.lower():
                    self.send_frame("Starting Python Remote Shell...")
                    auth = 1
                if "b" == decoded_payload.lower():
                    "Goodbye to our client..."
                    self.send_frame("Goodbye.")
                    return

        else:
            self.request.sendall("HTTP/1.1 400 Bad Request\r\n" +
                                 "Content-Type: text/plain\r\n" +
                                 "Connection: close\r\n" +
                                 "\r\n" +
                                 "Incorrect request")

        self.send_frame("\r\nReally starting shell...\r\n")

        logging.warning('1')
        # Add that function to the thread's scope.
        thread_scope.rfile = self.rfile
        thread_scope.wfile = self.wfile

        # Set up the environment for the repl, this makes halt() and Print()
        # available.
        repl_scope = dict(globals(), **locals())

        # Create the console object and pass the stream's rfile and wfile.
        self.console = InteractiveSocket(self.rfile, self.wfile,
                                         locals=repl_scope)

        # All errors except SystemExit are caught inside interact(), only
        # sys.exit() is escalated, in this situation we want to close the
        # connection, not kill the server ungracefully. We have halt()
        # to do that gracefully.
        try:
            self.console.interact()
        except SystemExit:
            Print("SystemExit reached, closing the connection.")
            self.finish()

    def shake_hand(self, key):
        # calculating response as per protocol RFC
        key = key + WS_MAGIC_STRING
        resp_key = base64.standard_b64encode(hashlib.sha1(key).digest())

        resp = "HTTP/1.1 101 Switching Protocols\r\n" + \
            "Upgrade: websocket\r\n" + \
            "Connection: Upgrade\r\n" + \
            "Sec-WebSocket-Accept: %s\r\n\r\n" % (resp_key)

        self.request.sendall(resp)

    def decode_frame(self, frame):
        opcode_and_fin = frame[0]

        # assuming it's masked, hence removing the mask bit(MSB) to get len. also assuming len is <125
        payload_len = frame[1] - 128

        mask = frame[2:6]
        encrypted_payload = frame[6: 6+payload_len]

        payload = bytearray([encrypted_payload[i] ^ mask[i % 4]
                            for i in range(payload_len)])

        print(payload)

        return payload

    def send_frame(self, payload):
        # setting fin to 1 and opcpde to 0x1
        frame = [129]
        # adding len. no masking hence not doing +128
        frame += [len(payload)]
        # adding payload
        frame_to_send = bytearray(frame) + payload

        self.request.sendall(frame_to_send)


class ThreadedTCPServer(ss.ThreadingMixIn, ss.TCPServer):
    # from https://stackoverflow.com/a/18858817
    # Ensures that the socket is available for rebind immediately.
    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(self.server_address)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Expose a Python REPL loop"
                                     " over a tcp socket.")
    parser.add_argument('-i', '--hostname', default=None,
                        help="Ip to bind to defaults to 0.0.0.0, will use "
                             "environment value of REPL_HOST if set.")
    parser.add_argument('-p', '--port', default=None, type=int,
                        help="Port to bind to. Defaults"
                        " to 8266, will use environment value of REPL_PORT if"
                        " set.")
    parser.add_argument('-k', '--kill-active', default=False,
                        action="store_true", help="Kill active connections on"
                        " interrupt signal.")

    args = parser.parse_args()

    if ("REPL_HOST" in os.environ) and args.hostname is None:
        args.hostname = os.environ["REPL_HOST"]

    if args.hostname is None:  # still None, go for fallback.
        args.hostname = "0.0.0.0"

    if "REPL_PORT" in os.environ and args.port is None:
        args.port = int(os.environ["REPL_PORT"])

    if (args.port is None):  # Still None, go for fallback.
        args.port = 8266

    # Create the server object and a thread to serve.
    server = ThreadedTCPServer((args.hostname, args.port), RequestPythonREPL)

    # set whether sending ctrl+c to the server will close it even if there are active connections.
    server.daemon_threads = args.kill_active

    # start the server thread
    server_thread = threading.Thread(target=server.serve_forever)

    # Exit the server thread when the main thread terminates
    server_thread.daemon = True

    # Start the server thread, which serves the RequestPythonREPL.
    server_thread.start()

    print("BIPES Project - Bridge started")
    print("Now, access the Python Console from a Web Browser using a WebREPL client")
    print("For example: https://micropython.org/webrepl/#127.0.0.1:8266/")

    # Ensure main thread does not quit unless we want it to.
    while not should_exit:
        time.sleep(1)

    # If we reach this point we are really shutting down the server.
    print("Shutting down.")
    server.server_close()
    server.shutdown()
    server_thread.join()
    # This does not always correctly release the socket, hence SO_REUSEADDR.
