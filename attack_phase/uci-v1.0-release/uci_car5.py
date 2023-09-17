import serial

ser = serial.Serial("/dev/ttyACM1", 115200)
a = ('p'*10).encode()
ser.write(a)
a = bytearray([2]*12)
ser.write(a)
a = '\n'.encode()
ser.write(a)
