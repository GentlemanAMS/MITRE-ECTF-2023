import matplotlib.pyplot as plt
import struct
randNumsFile = open("binary_out_10mil_hash", "rb")
s = randNumsFile.read()
#x = (len(s) // 4)
#d = (struct.unpack("I" * (x//2), s[:x*2]))
d = (struct.unpack("B" * len(s), s))
"""
chunk = len(s) // 13
binary_out = open("binary_out_whitened_max", "ab")
for j in range(1):
  z = 12
  d = (struct.unpack("B" * chunk, s[chunk*z:chunk*(z+1)]))
  
  prev_bit = 2
  new_bit = 0
  new_byte = 0
  idx = 0
  for x in d:
    for i in range (4):
      new_bit = (x >> i*2) & (0x3)
      prev_bit = (new_bit >> 1) & 0x1
      new_bit = new_bit & 0x1
      if (new_bit ^ prev_bit):
        if (idx >= 8):
          binary_out.write(struct.pack("B", new_byte))
          new_byte = 0
          idx = 0
        
        new_byte <<= 1
        new_byte |= new_bit
        idx += 1
        #print(new_byte)
      #prev_bit = new_bit


binary_out.close()
randNumsFile.close()
  
print("Done!")
"""
  

n, bins, patches = plt.hist(x=d, bins=256, color='#0504aa', alpha = 0.7, rwidth=0.85)
plt.grid(axis='y', alpha=0.75)
plt.xlabel('8-bit Int Value')
plt.ylabel('Frequency')
plt.title(str(len(s)) + ' 8-bit ADC Noise Histogram')
maxfreq = n.max()

plt.show()

randNumsFile.close()
