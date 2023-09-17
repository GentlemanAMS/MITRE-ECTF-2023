# given by MITRE in slack channel in a thread on 1/27

import serial

ser = serial.Serial('/dev/tty.<#>', 115200, timeout=0)

while True:
    data = ser.read(1)
    if len(data) == 1:
        print(data)