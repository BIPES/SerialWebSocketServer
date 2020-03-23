# SerialWebSocketServer
WebSocket server to bridge WebSocket TCP/IP stream to serial port / USB-serial port. Part of BIPES Project - http://www.bipes.net.br, to allow a Serial-USB device, such as a mBed or ESP8266 to be controlled, programmed and monitored from BIPES web application.

Usage:

1. Connect the device on the USB Port and check the device port (using dmesg, for example)
2. Select the USB Port (USB_PORT in Python source code)
3. Select the TCP/IP Socket Port (TCP_PORT in Python source code)
4. Run this program (python serialServer.py)
5. Access the USB device using a web browser and a WebSocket client
6. Web client example: https://micropython.org/webrepl/#127.0.0.1:1338/ (replace 127.0.0.1:1338 with the correct port and IP)


This code is based on PyWSocket, a "Simple WebSocket server in python. With <80 lines of code", available at https://github.com/sanketplus/PyWSocket
