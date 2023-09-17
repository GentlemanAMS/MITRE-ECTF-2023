# Importing required module
import os

# import argparse
#
# parser = argparse.ArgumentParser()
# parser.add_argument("--car-id", type=int, required=True)
# parser.add_argument("--pair-pin", type=int, required=True)
# args = parser.parse_args()


# checked how to grab serial ports of devices in Python. Check that stackoverflow thread again

# load car
os.system('python3 -m ectf_tools device.load_hw --dev-in CarOut --dev-name Car --dev-serial <SERIAL_PORT_Car>')
# load paired fob
os.system('python3 -m ectf_tools device.load_hw --dev-in PairedFobOut --dev-name PairedFob --dev-serial <SERIAL_PORT_Paired_Fob>')
# load load unpaired fob
os.system('python3 -m ectf_tools device.load_hw --dev-in UnPairedFobOut --dev-name UnPairedFob --dev-serial <SERIAL_PORT_Unpaired_Fob>')
