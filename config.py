# configuration

### U2F_V2 ###

# U2FHID protocol version identifier
PROTOCOL = 2
# device version number (major.minor.build)
DEVICE_VERSION = "1.0.0"
# Capabilities flags: CAPABILITY_WINK (0x01), CAPABILITY_CBOR (0x04), CAPABILITY_NMSG (0x08)
CAPABILITIES = 0x01 | 0x04

### CTAP2.0 ###

VERSIONS = ['U2F_V2', 'FIDO_2_0']
