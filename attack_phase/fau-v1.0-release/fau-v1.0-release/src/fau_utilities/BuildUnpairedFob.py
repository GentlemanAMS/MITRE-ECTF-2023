# Importing required module
import os

# import argparse
#
# parser = argparse.ArgumentParser()
# parser.add_argument("--car-id", type=int, required=True)
# parser.add_argument("--pair-pin", type=int, required=True)
# args = parser.parse_args()


# Build unpaired fob
os.system('python3 -m ectf_tools --debug build.fob --design 2023-ectf-insecure-example --name BuildEnv --deployment FAUDepl --fob-out UnPairedFobOut --fob-name UnpairedFob')
