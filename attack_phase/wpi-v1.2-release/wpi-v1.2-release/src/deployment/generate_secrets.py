import argparse
from pathlib import Path
import os
import json

KEY_SIZE = 32
SEED_SIZE = 32
NONCE_SIZE = 24
PASS_SIZE = 32

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--secret-file", type=Path, required=True)
    args = parser.parse_args()

    if os.path.isfile(args.secret_file):
        os.remove(args.secret_file)

    with open(args.secret_file, "w+") as f:
        f.write("{}")

if __name__ == "__main__":
    main()