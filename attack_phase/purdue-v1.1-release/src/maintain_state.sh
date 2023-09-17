#!/bin/bash

echo "Copying files from car to fob"

# list of files to be maintained
SFILES="board_link.c wrappers.c ustdlib.c"
IFILES="board_link.h wrapper.h ustdlib.h"

for file in $SFILES; do
    diff fob/src/$file car/src/$file
done

for file in $IFILES; do
    diff fob/inc/$file car/inc/$file
done

# copy the files from the fob to the backup directory
# Create a temp folder in _backup directory
backup_dir=_backup/$(date +%Y%m%d%H%M%S)
echo "Creating backup directory $backup_dir"
mkdir -p $backup_dir

for file in $SFILES; do
    cp fob/src/$file _backup/$(date +%Y%m%d%H%M%S)/$file
done

for file in $IFILES; do
    cp fob/inc/$file _backup/$(date +%Y%m%d%H%M%S)/$file
done

# Backup done, now copy the files from the car to the fob
for file in $SFILES; do
    cp car/src/$file fob/src/$file
done

for file in $IFILES; do
    cp car/inc/$file fob/inc/$file
done

echo "Done"
