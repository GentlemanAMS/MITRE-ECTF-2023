#!/usr/bin/python3 -u

import socket
import argparse
import time
import serial
import matplotlib.pyplot as plt
import sys
import os

# @brief Function to send commands to pair a new fob.
# @param unpairmed_fob_bridge, bridged serial connection to unpairmed fob
# @param pairmed_fob_bridge, bridged serial connection to pairmed fob
# @param pair_pin, pin used to pair a new fob
def pair():
    print("started...")
    # Connect to both sockets for serial
    
    string = "0123456789abcdef"
    first_half = "01234567"
    second_half= "89abcdef"
    prev = 0.1
    total = 0
    n = 0
    flag = False
    ser = serial.Serial("/dev/ttyACM0", 115200)
    for a in second_half:
        for b in string:
            for c in string:
                for d in string:
                    for e in string:
                        for f in string:
                            
                            trial = a + b + c + d + e + f 
                            print(trial)
                            n+=1
                            trial += "\n"
                            ser.write(b"pair\n")
                            bt = ser.read(1)
                            while(bt != b'P'):
                                bt = ser.read(1)
                            print(bt)
                            ser.write(trial.encode())
                            # start = time.time()
                            # ser.write(b"pair\n      \n")
                            # ser.read(1)
                            # end = time.time()
                            # total += (end - start)
                            # if(end - start) > 50*0.0012556412:
                            #     print(trial)
                            #     flag = True
                        if(flag):
                            break
                    if(flag):
                        break
                if(flag):
                    break
            if(flag):
                break
            # if(n > 10000):
            #     flag = True
            #     break
        if(flag):
            break
    print(total / n)
    
# @brief Main function
#
# Main function handles parsing arguments and passing them to pair
# function.
def main():
    pair()

if __name__=='__main__':
    main()
