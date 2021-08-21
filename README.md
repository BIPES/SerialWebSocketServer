# SerialWebSocketServer
A WebSocket server to bridge WebSocket TCP/IP stream to serial port / USB-serial port. Part of BIPES Project - http://www.bipes.net.br, to allow a remote Serial-USB device, such as Arduino, PyBoard, Raspberry Pi Pico, mBed or ESP8266 to be controlled, programmed and monitored remotely from BIPES web application. Needs a PC or Raspberry Pi with Linux to run this SerialWebSocketServer.

Usage:

1. Connect the device on the bridge device USB Port and check the device port (using dmesg, for example)
2. Select the USB Port (USB_PORT in Python source code)
3. Select the TCP/IP Socket Port (TCP_PORT in Python source code)
4. Run this program (python serialServer.py)
5. Access http://bipes.net.br/beta2/ui/, select the network option and connect to the bridge device

This code is based on PyWSocket, a "Simple WebSocket server in python. With <80 lines of code", available at https://github.com/sanketplus/PyWSocket
