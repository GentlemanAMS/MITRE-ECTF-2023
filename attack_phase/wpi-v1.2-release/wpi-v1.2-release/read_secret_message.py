import serial

ser = serial.Serial('/dev/ttyACM0', 115200)
a = ser.read(15).decode('utf-8')
print(a)
ser.write('Z'.encode())
a = ser.read(15)
print(a)
ser.write('Z'.encode())
a = ser.read(15)
print(a)
ser.write('Z'.encode())
a = ser.read(15)
print(a)
ser.write('Z'.encode())
a = ser.read(15)
print(a)
ser.write('Z'.encode())
