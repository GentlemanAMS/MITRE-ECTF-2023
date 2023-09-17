import serial
import time

ser1 = serial.Serial("/dev/ttyACM0", baudrate=115200)
string = "0123456789abcdef"
first_half = "89ab"
second_half = "89abcdef"
for a in first_half:
    for b in string:
        for c in string:
            for d in string:
                for e in string:
                    for f in string:            
                        trial = a + b + c + d + e + f + "\n"
                        print(trial[:-1])
                        trial = trial.encode()
                        ser1.write(b"pair")
                        ser1.write(trial)
                        time.sleep(0.001)

