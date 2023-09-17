import serial
import time
import subprocess

# Define the shell command to run
command = "./firmware_upload.sh"  # Update with the path and name of your shell script

ser = serial.Serial("/dev/ttyACM0", baudrate=115200)
ser1 = serial.Serial("/dev/ttyACM1", baudrate=115200)

with open('serial_data_response.txt', 'r') as file:
    data = file.read()
    data = data.replace('[', ', ')
    data = data.replace(']', ', ')
    data_list = list(map(int, filter(lambda x: x != '', data.replace('\n', '').split(','))))


print(data_list)

#print("Data tesing: ", data_list[16])
#data_bytes = bytes(data_list)

# # Open a file for writing
filename = 'serial_data_final.txt'  # Specify the filename
with open(filename, 'a') as file:
    print(f"Writing serial data to {filename}...")

ser.write(b'\x53')

def find_subarray(arr, subarr):
    n = len(arr)
    m = len(subarr)
    print("SUBARRAY ========== ", subarr)
    for i in range(n - m + 1):
        if arr[i:i + m] == subarr:
            return i
    return -1


        
challenge = ser.read(80)
print(f"RECEIVED CHALLENGE = {challenge}")
print([i for i in challenge])
challenge = [i for i in challenge]
challenge_int = int.from_bytes(challenge, byteorder='big')

index = find_subarray(data_list, challenge)
print("INDEX ++++  ",index)
if index != -1:
    print(f"Challenge found @ : {index}\n")
    
    response = data_list[index + 80: index + 80 + 80]
    

    ser.write("Y".encode())
    ser.write(bytes(response))
    print(f"RESPONSE SENT = {response} \n")

    x = ser1.read(63)
    print(x)

else:
    print("Challenge missing\n\n")
    ser.write(b"N")

    response_invalid = data_list[80: (80 + 80)]
    response_invalid_bytes = bytes(response_invalid)
    ser.write(response_invalid_bytes) # Som random crap, dw

    with open(filename, 'a') as file:
        file.write(str(challenge_int))  # Write data to file with a newline
        file.write("MISSED, BYE!"  + '\n\n')

ser.flush()

    
