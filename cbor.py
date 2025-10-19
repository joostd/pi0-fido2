# minimal CBOR encoding/decoding, as used in CTAP

# DECODING

def read(s,n):
    return s[:n], s[n:]

def decode_unsigned(s):
    b,s = read(s,1)
    i = int.from_bytes(b) & 0x1f
    if i < 24:
        return i, s
    else:
        match i:
            case 24:
                return int.from_bytes(s[:1], byteorder='big'), s[1:]
            case 25:
                return int.from_bytes(s[:2], byteorder='big'), s[2:]
            case 26:
                return int.from_bytes(s[:4], byteorder='big'), s[4:]
            case 27:
                return int.from_bytes(s[:8], byteorder='big'), s[8:]
            case 31:
                raise Exception("Indefinite-length structures not implemented")
            case _:
                raise Exception("cannot happen?")

def decode(s):
    peek = int.from_bytes(s[:1]) # peek at first byte to determine type
    major = (peek & 0xe0) >> 5 # major type 0..7
    match major:
        case 0: # unsigned integer
            return decode_unsigned(s)
        case 1: # Negative Integer
            i,s = decode_unsigned(s)
            return -1 -i, s
        case 2: # Byte String
            length,s = decode_unsigned(s)
            return read(s,length)
        case 3: # Text String (UTF-8)
            length,s = decode_unsigned(s)
            string,s = read(s,length)
            return string.decode(), s
        case 4: # Array of data items
            length,s = decode_unsigned(s)
            items = []
            while length > 0:
                item, s = decode(s)
                items = items + [item]
                length = length - 1
            return items, s                        
        case 5: # Map of pairs of data items
            length,s = decode_unsigned(s)
            items = {}
            while length > 0:
                k, s = decode(s)
                v, s = decode(s)
                items[k] = v
                length = length - 1
            return items, s                        
        case 6: # Semantic Tag
            raise Exception("CBOR type 6 (Semantic Tag) Not implemented")
        case 7: # Floating-Point Numbers and Simple Types
            # boolean only
            b,s = read(s,1)
            if b == b'\xf4':
                return False, s
            if b == b'\xf5':
                return True, s
            raise Exception("CBOR type 7 (Floating-Point Numbers and Simple Types) Not implemented")

# ENCODING

def encode_unsigned(i):
    if i < 24:
        return i.to_bytes(1)
    if i < 2 ** 8:
        return bytes([24]) + i.to_bytes(1)
    if i < 2 ** 16:
        return bytes([25]) + i.to_bytes(2)
    if i < 2 ** 32:
        return bytes([26]) + i.to_bytes(4)
    if i < 2 ** 64:
        return bytes([27]) + i.to_bytes(8)
    raise Exception(f"error encoding integer { i } - out of range")

def encode(x):
    match x:
        # bool is a subclass of int => match bool first
        case bool():
            return b'\xf5' if x else b'\xf4'
        case int():
            if x >= 0:
                major = 0 # positive int
                bs = encode_unsigned(x)
            else:
                major = 1 # negative int
                bs = encode_unsigned(-1 - x)
            return bytes([major << 5 | bs[0]]) + bs[1:] 
        case bytes():
            major = 2
            lenx = encode_unsigned(len(x))
            bs = lenx + x
            return bytes([major << 5 | bs[0]]) + bs[1:] 
        case str():
            major = 3
            lenx = encode_unsigned(len(x))
            bs = lenx + x.encode("utf-8")
            return bytes([major << 5 | bs[0]]) + bs[1:] 
        case list():
            major = 4
            lenx = encode_unsigned(len(x))
            bs = lenx + b''.join([encode(item) for item in x])
            return bytes([major << 5 | bs[0]]) + bs[1:] 
        case dict():
            major = 5
            lenx = encode_unsigned(len(x))
            bs = lenx + b''.join([encode(k) + encode(x[k]) for k in x])
            return bytes([major << 5 | bs[0]]) + bs[1:] 
        case _:
            raise Exception(f"type {type(x)} Not implemented")

hex = '3045022100b3f9c86cead461dcb1ba495ec7940245f34185cdd5151306bbc814ccd7ce91750220051c6a04ab680bdaad5f0ed066a2f3c54f6d54b4e4f66cd4040b3d0baf9b8f4d'
bin = bytes.fromhex(hex)

tests = {
    'f4' : False,
    'f5' : True,
    '01' : 1,
    '20' : -1,
    '1818' : 24,
    '37' : -24,
    '3818' : -25,
    '1a00010000' : 65536,
    '1affffffff' : 4294967295,
    '1bffffffffffffffff' : 18446744073709551615,
    '83010203' : [1, 2, 3],
    '83181f18201821' : [31,32,33],
    'a10101' : {1:1},
    '5847' + hex : bin,
    'a1065847' + hex : { 6: bin },
    'a1647369676ea1065847' + hex : {"sign": {6:bin}},
    #'a40182665532465f5632684649444f5f325f3003500000000000000000000000000000000004a362726bf5627570f564706c617400051904b0' : {1:["U2F_V2","FIDO_2_0"],3:16*b'\0',4:{"rk":True,"up":True,"plat":0},5:1200},
    'a101f5': {1:True}
}

if __name__ == '__main__':
  for test in tests:
    result, rest = decode(bytes.fromhex(test))
    print(test, "=>", tests[test], result, rest)
    print(test, "=>", tests[test], "" if tests[test] == result else result, rest.hex())
    assert tests[test] == result
    assert rest == b''
    result = encode(tests[test])
    print(test, "<=", tests[test], "" if bytes.fromhex(test) == result else result)
    print( bytes.fromhex(test), result)
    assert bytes.fromhex(test) == result

