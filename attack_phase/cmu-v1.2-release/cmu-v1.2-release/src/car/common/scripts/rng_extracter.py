#!/bin/env python
# ref https://blog.podkalicki.com/generating-true-random-numbers-using-floating-adc-input-myth-or-facts/
# outputs in Dieharder format and binary stream for NIST suite
import serial
import struct
import os

with serial.Serial('/dev/ttyACM0', 115200, timeout=100) as s:
    size = os.path.getsize('binary_out_2gb_hash')
    print('Completed', size, "bytes\n")
    binary_out = open("binary_out_2gb_hash", "ab")
    #dieharder_out = open("dieharder_out.txt", "w")
    #line = s.readline()
  
    n = 2000000000 #take 2 bill samples (2GB)
    if (n <= - size):
      print("Already read enough\n")
    else:
      n -= size
    #n = 100000 #take tiny 100k samples
    print("Today I will read " + str(n) + " bytes :)\n")
    #dieharder_out.write("type: d")
    #dieharder_out.write("count: {}".format(n))
    #dieharder_out.write("numbit: 32")
    for x in range(1, n):
      data = s.read(1);
      #sample = struct.unpack("<I", data)[0]
      
      binary_out.write(data)
      #dieharder_out.write("%10d" % sample)
      
      if (x % n == 0):
        print("Now " + str(x / n) + "% done! \n")
   
    print("All done! :)\n")
    binary_out.close()
    #dieharder_out.close()
