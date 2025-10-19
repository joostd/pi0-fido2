#!/bin/bash

# Configure USB gadget through configfs
# see https://docs.kernel.org/usb/gadget_configfs.html

# requires libcomposite

# For use on a device with a USB Device Controller

# Configuration > interfaces / function
#

VID=0x0150
PID=0x0120
MANUFACTURER=FIDO
PRODUCT="Security Key"

# English language code is 0x409
LANG=0x409

lsmod | grep -q libcomposite || echo libcomposite not loaded
echo configfs mount:
mount -t configfs

CONFIGFS_HOME=/sys/kernel/config
cd $CONFIGFS_HOME/usb_gadget/

mkdir -p securitykey
cd securitykey

echo $VID > idVendor 
echo $PID > idProduct 
echo 0x0100 > bcdDevice 
echo 0x0200 > bcdUSB 

# Product strings
mkdir -p strings/$LANG
# echo "123456" > strings/$LANG/serialnumber
echo "$MANUFACTURER" > strings/$LANG/manufacturer
echo "$PRODUCT" > strings/$LANG/product

# Configurations
mkdir -p configs/c.1
echo 250 > configs/c.1/MaxPower
mkdir -p configs/c.1/strings/$LANG
echo "Config 1: HID device" > configs/c.1/strings/$LANG/configuration

# Functions
# usb_f_hid.ko gets loaded with request_module()
mkdir -p functions/hid.usb0
echo 1 > functions/hid.usb0/protocol
echo 1 > functions/hid.usb0/subclass
echo 8 > functions/hid.usb0/report_length
# report descriptor
echo 06 d0f1 0901 a101 0920 1500 26ff00 7508 9540 8102 0921 1500 26ff00 7508 9540 9102 c0 | xxd -r -p > functions/hid.usb0/report_desc

# associate function with configuration
ln -s functions/hid.usb0 configs/c.1/

# enable gadget so that the USB host can enumerate it
# bind gadget to USB Device Controller:
ls /sys/class/udc > UDC
