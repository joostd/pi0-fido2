#!/bin/bash

cd /sys/kernel/config/usb_gadget/
cd securitykey


# disable the gadget
echo "" > UDC
# Remove functions from configurations:
rm configs/c.1/hid.usb0

# Remove strings directories in configurations:
rmdir configs/c.1/strings/0x409

# remove the configurations:
rmdir configs/c.1

# Remove functions
rmdir functions/hid.usb0

# Remove strings directories in the gadget:
rmdir strings/0x409
# remove the gadget:
cd ..
rmdir securitykey/
