import serial
import time

ser = serial.Serial("/dev/ttyACM0", baudrate=115200)
string = "0123456789abcdef"
first_half = "12673450"
second_half = "def"
for a in first_half:
    for b in string:
        for c in string:
            for d in string:
                for e in string:
                    for f in string:            
                        ser.write(b"pair\n")
                        ser.read(11)
                        trial = a + b + c + d + e + f + "\n"
                        print(trial[:-1])
                        trial = trial.encode()
                        ser.write(trial)

