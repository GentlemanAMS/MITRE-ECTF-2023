import serial
import time
import sys

ser1 = serial.Serial("/dev/ttyACM0", baudrate=115200)
ser2 = serial.Serial("/dev/ttyACM1", baudrate=921600)
string = "0123456789abcdef"
first_half = "5"
second_half = "89abcdef"
ser2.write(b'\x01')
for a in first_half:
    for b in string:
        for c in string:
            for d in string:
                for e in string:
                    for f in string:            
                        trial = a + b + c + d + e + f
                        print(trial)
                        trial = bytes.fromhex(trial)
                        
                        x = ser2.read(1)
                        while (x != b'\x50'):
                            x = ser2.read(1)

                        print("Received Start")

                        ser1.write(b'\x40')
                        ser1.write(trial)
                         
                        character= ser2.read(1)
                        if (character == b'\x44'):
                            fl = open("Answer.txt", 'a')
                            fl.write(a)
                            fl.write(b)
                            fl.write(c)
                            fl.write(d)
                            fl.write(e)
                            fl.write(f)
                            print("Done")
                            print(a+b+c+d+e+f)
                            sys.exit()
                        
                        elif (character == b'\x45'):
                            print("Not this one")
                            pass

                        else:
                            print(character)
                            print("Something wrong")


                        

