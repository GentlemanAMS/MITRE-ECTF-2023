# Importing required module
import os

# import argparse
#
# parser = argparse.ArgumentParser()
# parser.add_argument("--car-id", type=int, required=True)
# parser.add_argument("--pair-pin", type=int, required=True)
# args = parser.parse_args()


# checked how to grab serial ports of devices in Python. Check that stackoverflow thread again

# bridge unpaired fob
os.system('python3 -m ectf_tools device.bridge --bridge-id <INET_SOCKET> --dev-serial <SERIAL_PORT_UnPaired_Fob>')
