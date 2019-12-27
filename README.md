# pi0-fido2
FIDO2 roaming authenticator implementation using a Raspberry Pi zero

# Bill of Materials

Required:

- [Raspberry Pi Zero](https://www.raspberrypi.org/products/raspberry-pi-zero/) (WiFi is not used so no need for the more expensive Pi Zero W)
- SD card (8 GB is more than enough)
- USB cable (micro USB B male to whatever your computer uses, eg USB A male or USB C male)

Optional:

- [Adafruit Infineon Trust M Breakout Board](https://www.adafruit.com/product/4351) (for protection against cloning)
- [Qwiic button](https://www.sparkfun.com/products/15585) (for User Presence)
- [SparkFun Qwiic SHIM for Raspberry Pi](https://www.sparkfun.com/products/15794) (when using Qwicc/Stemma boards)
- [2x20-pin strip male header](https://www.adafruit.com/product/2822) (when using Qwicc/Stemma boards)
- [Qwiic Cable](https://www.sparkfun.com/products/14426) (0-2, one for each Qwicc/Stemma devices used)

Total costs: around 10-20 USD.

# Use cases

Primary use case is testing FIDO2 clients using a real USB-HID device. But using the secure element you can build one for production use.

# See also

[U2FDevice](https://github.com/Crystalix007/U2FDevice) - A program to allow Raspberry Pi Zeros to act as U2F tokens
.
a similar project implemented in C++, but without cloning protection and CTAP2 support.
