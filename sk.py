#!/usr/bin/env python3

import sys
import os
import time
import struct
import logging
import argparse

import secrets
#from fido2 import cbor
from hashlib import sha256
from cryptography import x509, exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

import config
import cbor

HID_RPT_SIZE = 64

# hard-coded
attestation_key = ec.derive_private_key(int('f3fccc0d00d8031954f90864d43c247f4bf5f0665c6b50cc17749a27d1cf7664', 16), ec.SECP256R1(), default_backend())
assert attestation_key.public_key().public_bytes(encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint) == \
       bytes.fromhex('048d617e65c9508e64bcc5673ac82a6799da3c1446682c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf0203b4b8911ba0569994e101')

attestation_cert = bytes.fromhex('''
3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce3d04030230173115
30130603550403130c476e756262792050696c6f74301e170d3132303831343138323933325a170d
3133303831343138323933325a3031312f302d0603550403132650696c6f74476e756262792d302e
342e312d34373930313238303030313135353935373335323059301306072a8648ce3d020106082a
8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c1446682c258c463fffdf58
dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf0203b4b8911ba0569994e101300a06082a
8648ce3d0403020347003044022060cdb6061e9c22262d1aac1d96d8c70829b2366531dda268832c
b836bcd30dfa0220631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df
''')
assert x509.load_der_x509_certificate(attestation_cert).public_key().public_bytes(encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint) == \
       bytes.fromhex('048d617e65c9508e64bcc5673ac82a6799da3c1446682c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf0203b4b8911ba0569994e101')

# TODO: store metadata with keys (eg RP ID)
keys = {}


def gen_id():
    """generate a unique 4-byte ID"""
    id = 0xabcdef00
    def next_id():
        nonlocal id
        id = (id + 1) % 2**32
        return struct.pack(">L",id)
    return next_id

new_channelID = gen_id()

def new_key():
    private_key = ec.generate_private_key( ec.SECP256R1())
    public_key = private_key.public_key().public_bytes(encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint)
    key_handle = secrets.token_bytes(16) # 64
    return private_key, public_key, key_handle

def read_request(client):
    """ read request packets from CTAP client"""
    message = b''
    message_size = 0
    channelID = None
    cmd = None
    while True:
        # read request packet from source device
        packet = client.read(HID_RPT_SIZE)
        if packet==None:
            continue
        logger.debug(f"< HID {packet.hex()}")
        if not channelID:
            channelID = packet[0:4]
        else:
            assert channelID == packet[0:4] # assume no concurrent use
        if( packet[4]&0x80 ): # initialization packet
            cmd = packet[4:5]
            (message_size,) = struct.unpack(">H", packet[5:7])
            data = packet[7:7+message_size] # may be fragmented
            message = data
            # logger.debug(f"=== [{channelID.hex()}] {cmd.hex()} {data.hex()} ({len(data)} bytes), {len(message)}/{message_size} bytes")
        else: # continuation packet
            seq = packet[4]
            remaining = message_size - len(message)
            data = packet[5:5+remaining]
            message += data
            # logger.debug(f"=== [{channelID.hex()}] #{hex(seq)} {data.hex()} ({len(data)} bytes), {len(message)}/{message_size} bytes")
        if len(message) >= message_size:
            break
        else:
            pass
            # logger.debug(f"=== {message_size - len(message)} bytes remaining")
    assert message_size == len(message)
    cmd = cmd[0]&0x7f
    logger.info(f"<< U2FHID cmd={hex(cmd)} {message.hex()}")
    return channelID, cmd, message

def send_response(client, channelID, cmd, response):
    """ send response packets to CTAP client"""
    # fragment response into initialization packet + continuation packets
    data = response
    # initialization pakcet
    packet = channelID + struct.pack("B",cmd|0x80) + struct.pack(">H", len(data)) + data
    data = packet[HID_RPT_SIZE:]
    packet = pad0(packet[:HID_RPT_SIZE])
    logger.debug(f"> HID {packet.hex()}")
    client.write(packet)
    client.flush()
    seq = 0
    while len(data) > 0:
        # continuation packet
        packet = channelID + struct.pack("B",seq) + data
        seq += 1
        data = packet[HID_RPT_SIZE:]
        packet = pad0(packet[:HID_RPT_SIZE])
        logger.debug(f"> HID {packet.hex()}")
        client.write(packet)
        client.flush()
    logger.info(f">> U2FHID cmd={hex(cmd)} {response.hex()}")

def handle_u2f_command(request):
    request_apdu = request
    cla = request_apdu[0]
    ins = request_apdu[1]
    p1 = request_apdu[2]
    p2 = request_apdu[3]
    lc = b'\0' + request_apdu[4:7] # TODO: check always LC1-3?
    (lc,) = struct.unpack(">I", lc)
    request_data = request_apdu[7:7+lc]
    le = request_apdu[7+lc:]
    (le,) = struct.unpack(">H", le)
    assert cla == 0
    if cla != 0x00:
        return b'', bytes.fromhex("6e00") # SW_CLA_NOT_SUPPORTED
    logger.debug(f"<<< CLA={cla} INS={ins} P1={p1} P2={p2} Lc={lc} DATA={request_data.hex()} Le={le}")
    match ins:
        case 0x01: # U2F_REGISTER
            assert p1 in [ 0x00, 0x03 ] # TODO
            assert p2 == 0x00
            assert lc == 64
            challenge = request_data[:32]
            application = request_data[32:64]
            logger.info(f"<<<< U2F_REGISTER challenge={challenge.hex()} application={application.hex()}")
            # create a credential and generate a response
            private_key, public_key, key_handle = new_key()
            keys[key_handle] = {
                'type': 'u2f',
                'private_key': private_key,
                'hash': application,
                'counter': 0,
            }
            data_to_sign = b'\00' + application + challenge + key_handle + public_key
            signature = attestation_key.sign( data_to_sign, ec.ECDSA(hashes.SHA256()))
            return b'\05' + public_key + bytes([len(key_handle)]) + key_handle + attestation_cert + signature, bytes.fromhex("9000")
        case 0x02: # U2F_AUTHENTICATE
            assert p1 in [ 0x03, 0x07, 0x08 ]
            assert p2 == 0x00
            challenge = request_data[:32]
            application = request_data[32:64]
            key_handle_length = request_data[64]
            key_handle = request_data[65:]
            assert len(key_handle) == key_handle_length
            logger.info(f"<<<< U2F_AUTHENTICATE p1={p1} challenge={challenge.hex()} application={application.hex()} key_handle={key_handle.hex()}")
            try:
                entry = keys[key_handle]
                if entry['type'] != 'u2f' or entry['hash'] != application:
                    return b'', bytes.fromhex("6A80") # SW_WRONG_DATA (invalid key handle for this application or protocol)
            except KeyError:
                return b'', bytes.fromhex("6A80") # SW_WRONG_DATA (invalid key handle)
            match p1:
                case 0x07: # "check-only"
                    return b'', bytes.fromhex("6985") # SW_CONDITIONS_NOT_SATISFIED
                case 0x03: # "enforce-user-presence-and-sign"
                    up = bytes([0x01]) # fake User Presence
                case 0x08: # "dont-enforce-user-presence-and-sign"
                    up = bytes([0x00])
            counter = entry['counter']
            entry['counter'] += 1
            counter = struct.pack(">I", counter)
            private_key = entry['private_key']
            data_to_sign = application + up + counter + challenge
            signature = private_key.sign( data_to_sign, ec.ECDSA(hashes.SHA256()))
            return up + counter + signature, bytes.fromhex("9000")
        case 0x03: # U2F_VERSION
            assert p1 == 0x00
            assert p2 == 0x00
            return b'U2F_V2', bytes.fromhex("9000")
        case _:
            return b'', bytes.fromhex("6d00") # SW_INS_NOT_SUPPORTED


def handle(cmd, request):
    match cmd:
        case 0x03: # CTAP_MSG
            response, sw = handle_u2f_command(request)
            logger.debug(f">>> DATA={response.hex()} SW={sw.hex()}") # TODO move into handle_u2f
            return cmd, response+sw
        case 0x06: # CTAP_INIT
            nonce = request
            assert len(nonce) == 8
            channelID = new_channelID()
            assert len(channelID) == 4
            protocol = 2    # U2FHID protocol version identifier
            major, minor, build = [int(n) for n in config.DEVICE_VERSION.split('.')]
            capabilities = config.CAPABILITIES # CAPABILITY_WINK
            info = struct.pack("BBBBB", protocol, major, minor, build, capabilities)
            data = nonce + channelID + info
            assert len(data) == 17
            return cmd, data
        case 0x08: # CTAPHID_WINK
            print('\a', end='') # instead of flashing an LED, print the BELL character
            return cmd, b''
        case 0x10: # CTAPHID_CBOR
            return cmd, ctap2(request)
        case _:
            return 0x3f, b'\1' # ERR_INVALID_CMD

def pad0(m,size=HID_RPT_SIZE):
  return (m + size * b'\0')[:size]


def ctap2(request):
    cmd = request[0]
    match cmd:
        case 0x01: # authenticatorMakeCredential
            args,_ = cbor.decode(request[1:])
            clientDataHash = args[1]
            rp = args[2]
            rpID = rp['id']
            user = args[3]
            userID = user['id']
            userName = user['name']
            pubKeyCredParams = args[4]
            if {"alg": -7, "type": "public-key"} not in pubKeyCredParams:
                return b'\x26' # CTAP2_ERR_UNSUPPORTED_ALGORITHM
            logger.info(f"authenticatorMakeCredential clientDataHash={clientDataHash.hex()} rp={rp} user={user}")
            if 5 in args:
                excludeList = args[5]
                logger.info(f"TODO excludeList={excludeList}")
            if 6 in args:
                extensions = args[6]
                logger.info(f"TODO extensions={extensions}")
            if 7 in args:
                options = args[7]
                logger.info(f"TODO options={options}")
            if 8 in args:
                pinAuth = args[8]
                logger.info(f"TODO pinAuth={pinAuth}")
            if 9 in args:
                pinProtocol = args[9]
                logger.info(f"TODO pinProtocol={pinProtocol}")
            logger.info(args)
            #return b'\x28'    # CTAP2_ERR_KEY_STORE_FULL
            #return b'\1'    # CTAP1_ERR_INVALID_COMMAND
            rpIdHash = sha256(rpID.encode('utf-8')).digest()
            flags = b'\1' # UP
            signCount = 4*b'\0'
            aaguid = 16*b'\0'
            # TODO
            credentialId = bytes.fromhex('88888888888888889999999999999999aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccddddddddddddddddeeeeeeeeeeeeeeeeffffffffffffffff')
            credentialIdLength = struct.pack(">H", len(credentialId))
            credentialPublicKey = cbor.encode({
                1: 2,
                3: -7,
                -1: 1,
                -2: bytes.fromhex('5642119411d801b3171bf15ed8c1413a119d31b79271cbe7cc5fa40cfcd9a58d'),
                -3: bytes.fromhex('b3bd19905d2894e1b92a33e84297ca97f38a6c87659a6433362e24b28052b35a'),
            })
            attestedCredentialData = aaguid + credentialIdLength + credentialId + credentialPublicKey
            authData = rpIdHash + flags + signCount + attestedCredentialData
            fmt = "packed"
            attStmt = {} # don't support attestation
            attStmt = {
                "alg": -7,
                "sig": bytes.fromhex('30440220188e8ac1280605e0356336711d61b5e8ea4ac85362f681fb1e405cf02dbcb736022037c5a95ee4e08e83ed59c665ade3e16e3ddf72dc7b26d1bc6242cf4024a7516f'),
                "x5c": [
                    bytes.fromhex('308202d9308201c1a003020102020900c8e7894577899dfc300d06092a864886f70d01010b0500302e312c302a0603550403132359756269636f2055324620526f6f742043412053657269616c203435373230303633313020170d3134303830313030303030305a180f32303530303930343030303030305a306f310b300906035504061302534531123010060355040a0c0959756269636f20414231223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e3128302606035504030c1f59756269636f205532462045452053657269616c20313136363636353637323059301306072a8648ce3d020106082a8648ce3d030107034200047296bd1c3793013f969f26acf1330dd42fb0b31ccae7ab21097f63b9d2a8d40cb0a4f903521382f43faf697cea369841539e081c2fc0a40dc83f67faf8edaedda38181307f3013060a2b0601040182c40a0d0104050403050403302206092b0601040182c40a020415312e332e362e312e342e312e34313438322e312e373013060b2b0601040182e51c0201010404030205203021060b2b0601040182e51c01010404120410ee882879721c491397753dfcce97072a300c0603551d130101ff04023000300d06092a864886f70d01010b0500038201010095803a85427458b670e084385540b94aabef1da7ff676dae5c0976927aae915dd0fc747b8a0a52f80163271683ce1fdf0a2082bb4c6a2ac93a701230a46451a831930a10a2ddca75108fc99e0383aca9e76224d49c33276d656e4bd89f9d2d632ccd116136f930cc3c7cdcf25dafe5be4db08e969d7f1e4eb7e1defc3183626a8f3f4af333ccc0204cf4056eb8fb3c70ae6d91ac8a56c917cc0aefae00e20970427dc1d2da65bba123787fab35321120a7e1b18f9d7e912720312bfa4b2e15032d182ffb8403282373a377ec2c2a1a2f931c8215dcac289b2d89728e2cb8d666387b1e64e56a99605d8edff58127f0b424bb6d3b8eaf1a37f386b574dee1eae9'),
                ],
            }
            return b'\0' + cbor.encode({
                1: authData,
                2: fmt,
                3: attStmt,
                })
        case 0x04: # authenticatorGetInfo
            assert len(request) == 1
            info = cbor.encode({
                1: config.VERSIONS,  # versions
                #2: ["credProtect", "hmac-secret"],
                3: 16*b'\0',    # aaguid
                4: {    # options
                    'rk': True,
                    'up': True,
                    'plat': False,
                    #'clientPin': true,
                    #'credentialMgmtPreview': true,
                   },
                5: 1200,
                #6: [2, 1],
                #7: 8,
                #8: 128,
                #9: ["usb"],
                #10: [{"alg": -7, "type": "public-key"}, {"alg": -8, "type": "public-key"}],
                #13: 4,
                #14: 328707,
            })
            return b'\0' + info


        case 0x06: # authenticatorClientPIN
            args,_ = cbor.decode(request[1:])
            logger.info(args)
            subCommand = args[2]
            match subCommand:
                case 0x01:  # getPINRetries
                    return b'\0' + cbor.encode(8)
                case 0x07:  # getUVRetries
                    return b'\0' + cbor.encode(3)
                case _:
                    return b'\1'    # CTAP1_ERR_INVALID_COMMAND
        case _:
            return b'\1'    # CTAP1_ERR_INVALID_COMMAND

# Parser

parser = argparse.ArgumentParser(
                    prog='sk.py',
                    description='Python Security Key',
                    epilog='Have a nice day!')
parser.add_argument('-c', '--client', default="/dev/hidg0", help="client (host) device file to use")
parser.add_argument('-l', '--log', default="info" )
parser.add_argument('-v', '--verbose', action='store_true')

args = parser.parse_args()

# Logger

loglevel = args.log.upper()
logger = logging.getLogger(__name__)
numeric_level = getattr(logging, loglevel, None)
if not isinstance(numeric_level, int):
    raise ValueError('Invalid log level: %s' % loglevel)
logging.basicConfig(level=numeric_level, format='%(message)s')

# devices

client = None

try:
    client = open(args.client, 'rb+')
    logger.info('Security Key started')

    while True:
        channelID, cmd, request = read_request(client)
        cmd, response = handle(cmd, request)
        send_response(client, channelID, cmd, response)
        print()
except PermissionError as e:
    sys.exit("need root")
except KeyboardInterrupt:
    sys.exit("\nSecurity Key stopped")
