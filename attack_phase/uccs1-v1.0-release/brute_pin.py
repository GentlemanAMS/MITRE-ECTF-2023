import serial
import time

ser1 = serial.Serial("/dev/ttyACM0", baudrate=115200)
ser2 = serial.Serial("/dev/ttyACM1", baudrate = 921600)
string = "0123456789abcdef"
first_half = "01234567"
second_half = "89abcdef"
for a in first_half:
    for b in string:
        for c in string:
            for d in string:
                for e in string:
                    if ((e == '0') or (e == '5') or (e == 'b')):
                        ser2.write(b'R')
                        time.sleep(0.04)
                    for f in string:            
                        trial = a + b + c + d + e + f + "\n"
                        print(trial[:-1])
                        trial = trial.encode()
                        ser1.write(b"pair\n")
                        bt = ser1.read(1)
                        print(bt)
                        while(bt != b'P'):
                            print(bt)
                            bt = ser1.read(1)
                        ser1.write(trial)
                        time.sleep(0.001)


