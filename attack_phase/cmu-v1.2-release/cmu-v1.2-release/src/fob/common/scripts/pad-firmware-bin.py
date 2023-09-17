# Pad the bootloader.bin with random bytes to 
# make it exactly 115 pages in size.

import logging
import os
import sys

logging.basicConfig(level=logging.DEBUG)
bootloader_file = sys.argv[1]
required_size = 0x400 * 110 # FW_FLASH_PAGES = 110 in ectf_tools/device.py
# THE FREE SPACE FROM 0x23800 to 0x40000 is not flashed.

stats = os.stat(bootloader_file)
logging.info(f"File size is : {stats.st_size}")

required_padding = required_size - stats.st_size

if required_padding < 0:
    logging.error(f"Too big bootloader already.")
    exit(1)
else:
    padding = os.urandom(required_padding)
    with open(bootloader_file, "ab") as bootloader:
        bootloader.write(padding)
    
    # Now finally verify the size.
    stats2 = os.stat(bootloader_file)
    assert stats2.st_size == required_size, "bootloader.bin not good."
    logging.info(f"Padded bootloader.bin")
    logging.info(f"File size is : {stats2.st_size}")

