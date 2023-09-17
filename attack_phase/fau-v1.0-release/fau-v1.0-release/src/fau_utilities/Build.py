# Importing required module
import os

import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--car-id", type=int, required=True)
parser.add_argument("--pair-pin", type=int, required=True)
args = parser.parse_args()

# Build building env
os.system('python3 -m ectf_tools --debug build.env --design 2023-ectf-insecure-example --name BuildEnv')
# Build tools needed
os.system('python3 -m ectf_tools --debug build.tools --design 2023-ectf-insecure-example --name BuildEnv')
# Build Deployment
os.system('python3 -m ectf_tools --debug build.depl --design 2023-ectf-insecure-example --name BuildEnv --deployment FAUDepl')
# Build car and paired fob
os.system('python3 -m ectf_tools --debug build.car_fob_pair --design 2023-ectf-insecure-example --name BuildEnv --deployment FAUDepl --car-out CarOut --fob-out PairedFobOut --car-name Car --fob-name PairedFob --car-id ' + str(args.car_id) + ' --pair-pin ' + str(args.pair_pin))
