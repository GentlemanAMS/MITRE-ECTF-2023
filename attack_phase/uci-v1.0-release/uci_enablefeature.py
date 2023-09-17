import serial
import time

ser1 = serial.Serial("/dev/ttyACM0", baudrate=115200)
ser1.write(b"pair\n");
#while(True):
    #print(ser1.read(1))


