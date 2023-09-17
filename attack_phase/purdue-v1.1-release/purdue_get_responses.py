import serial
import time
import subprocess

# Define the shell command to run
#command = "./firmware_upload.sh"  # Update with the path and name of your shell script

ser = serial.Serial("/dev/ttyACM1", baudrate=115200)

with open('serial_data.txt', 'r') as file:
    data = file.read()
    data_list = list(map(int, filter(lambda x: x != '', data.replace('\n', '').split(','))))

data_bytes = bytes(data_list)

# Open a file for writing
filename = 'serial_data_response.txt'  # Specify the filename
with open(filename, 'a') as file:
    print(f"Writing serial data to {filename}...")

data = b"0"
i = 0


while True:
    while data!=b"R":
        data = ser.read()
    
    print(f"REQUEST CHALLENGE: {data}")
        #file.write(data)  # Write data to file with a newline

    challenge = data_bytes[i:i+80]
    ser.write(challenge)
    print(f"SENT CHALLENGE = {challenge} ")
    

    response = ser.readline().decode().strip() 
    print(f"RECEIVED RESPONSE = {response} \n")

    #subprocess.call(command, shell=True) # Call the shell command and wait for it to complete

    data = b"0"
    with open(filename, 'a') as file:
        file.write(str(data_list[i:i+80])  + '\n')  # Write data to file with a newline
        file.write(response  + '\n\n')  # Write data to file with a newline

    i = i+80
    
