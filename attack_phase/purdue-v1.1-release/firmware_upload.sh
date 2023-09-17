#!/bin/bash

source env/bin/activate

python3 -m ectf_tools device.load_sec_hw --dev-in ./firmware/car2_cloned_fob_flag/ --dev-name car2-protected --dev-serial /dev/ttyACM0

deactivate
