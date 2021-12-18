#!/usr/bin/python
#Sat Mar 14 19:00:55 -03 2020
#Rafael Aroca <aroca@ufscar.br>

#WebSocket to Serial USB bridge
#Part of BIPES Project - Block based Integrated Platform for Embedded Systems
#http://www.bipes.net.br

#Based on PyWSocket by Sanket 
#https://superuser.blog/websocket-server-python/
#https://tools.ietf.org/id/draft-ietf-hybi-thewebsocketprotocol-09.html
#https://github.com/sanketplus/PyWSocket

#1. Select the USB Port
#2. Select the TCP/IP Socket Port
#3. Connect the device on the USB Port
#4. Run this program (python serialServer.py)
#5. Access the USB device using a web browser
#5. Web client example: https://micropython.org/webrepl/#127.0.0.1:1338/

USB_PORT="/dev/ttyACM0" # or /dev/ttyUSB0
TCP_PORT=1338

import SocketServer
import hashlib
import base64
import fcntl, os

import serial
import threading

WS_MAGIC_STRING = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

class MyTCPHandler(SocketServer.BaseRequestHandler):

    global com

    def handle(self):
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

	    self.send_frame("Welcome to BIPES Project! \r\n")
	    self.send_frame("You are remotely connecting to a USB device \r\n")
            while True:

		payload=""

		while com.inWaiting():
			data = com.read(com.inWaiting() )
			if not data:
				pass
			else:
				#print "COM: " + data
				self.send_frame(data)


		self.request.settimeout(0.1)
		try:
			payload = self.decode_frame(bytearray(self.request.recv(1024).strip()))
		except:
			pass

		if len(payload) >= 1:
			decoded_payload = payload.decode('utf-8')
			#print "NET: " + decoded_payload
			#self.send_frame("R:")
			#self.send_frame(payload)

			#### Send data by serial port!
			try:
				if ord(payload) == 3:
					com.sendbreak()
					pass
			except:
				pass
			com.write(payload)

        else:
            self.request.sendall("HTTP/1.1 400 Bad Request\r\n" + \
                                 "Content-Type: text/plain\r\n" + \
                                 "Connection: close\r\n" + \
                                 "\r\n" + \
                                 "Incorrect request")

    def shake_hand(self,key):
        # calculating response as per protocol RFC
        key = key + WS_MAGIC_STRING
        resp_key = base64.standard_b64encode(hashlib.sha1(key).digest())

        resp="HTTP/1.1 101 Switching Protocols\r\n" + \
             "Upgrade: websocket\r\n" + \
             "Connection: Upgrade\r\n" + \
             "Sec-WebSocket-Accept: %s\r\n\r\n"%(resp_key)

        self.request.sendall(resp)

    def decode_frame(self,frame):
        opcode_and_fin = frame[0]

        # assuming it's masked, hence removing the mask bit(MSB) to get len. also assuming len is <125
        payload_len = frame[1] - 128

        mask = frame [2:6]
        encrypted_payload = frame [6: 6+payload_len]

        payload = bytearray([ encrypted_payload[i] ^ mask[i%4] for i in range(payload_len)])

	print payload

        return payload

    def send_frame(self, payload):
	total = len(payload)
	sent=0

	while sent<total:

		payloadL = payload[sent:sent+100]

		# setting fin to 1 and opcpde to 0x1
		frame = [129]
		# adding len. no masking hence not doing +128
		frame += [len(payloadL)]
		# adding payload
		frame_to_send = bytearray(frame) + payloadL

		self.request.sendall(frame_to_send)

		sent = sent + 100



if __name__ == "__main__":
    HOST, PORT = "localhost", TCP_PORT

    # Serial port
    global com
    com = serial.Serial(USB_PORT)
    # sensible defaults
    com.baudrate = 115200
    com.timeout = 0
    com.bytesize = serial.EIGHTBITS
    com.parity = serial.PARITY_NONE
    com.stopbits = serial.STOPBITS_ONE
    com.xonxoff = 0
    com.rtscts = 0
    com.close()
    com.open()

    # Create the server, binding to localhost on port 9999
    print("BIPES Project - Bridge started")
    print("Now, access the USB from a Web Browser using a WebREPL client")
    print("For example: https://micropython.org/webrepl/#127.0.0.1:1338/")
    server = SocketServer.TCPServer((HOST, PORT), MyTCPHandler)
    server.serve_forever()
    
