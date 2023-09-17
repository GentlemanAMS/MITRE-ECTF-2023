import serial

ser = serial.Serial("/dev/ttyACM0", baudrate=115200)
#ser1 = serial.Serial("/dev/ttyACM0", baudrate=115200)
ser.write(b"pair\n")
#ser1.write(b'pair\n')
#ser1.read(1)
ser.read(1)
ser.write(b"0" * 12 + b"\xf8\x1b" + chr(0).encode() + b"\x20" + b'0' * 28 + b"\xdd\x8a" + b"\n")
#while(True):
#    print(ser1.read(1))
ser.close()
#ser1.close()

