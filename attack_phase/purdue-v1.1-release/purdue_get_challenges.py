import serial
import time
import subprocess

# Define the shell command to run
command = "./firmware_upload.sh"  # Update with the path and name of your shell script

ser = serial.Serial("/dev/ttyACM1", baudrate=115200)

# Open a file for writing
filename = 'serial_data.txt'  # Specify the filename
with open(filename, 'a') as file:
    print(f"Writing serial data to {filename}...")

data = b"0"

while True:
    
    
    while data!=b"S":
        data = ser.read()
        print(f"{data}")
        #file.write(data)  # Write data to file with a newline


    if b"S" in data:
        print("Firmware update recquested")
        subprocess.call(command, shell=True) # Call the shell command and wait for it to complete
        
        start_mc = "A"
        
        ser.write(start_mc.encode())

    challenge = ser.readline().decode().strip() 
    print(f"RECEIVED Nonce = {challenge} ")

    data = b"0"
    with open(filename, 'a') as file:
        file.write(challenge  + '\n')  # Write data to file with a newline
