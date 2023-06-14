from enum import Enum
import base58
from utils.common import strip_leading_0x

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


class BitcoinAddressType(Enum):
    P2PKH = 0
    P2SH = 1
    P2WPKH = 2
    P2WSH = 3


def get_btc_address_type(addr: str) -> BitcoinAddressType:
    if addr[0] == '1':
        return BitcoinAddressType.P2PKH
    elif addr[0] == '3':
        return BitcoinAddressType.P2SH
    elif addr[0:3] == 'bc1' and len(addr) == 42:
        return BitcoinAddressType.P2WPKH
    elif addr[0:3] == 'bc1' and len(addr) == 62:
        return BitcoinAddressType.P2WSH
    else:
        raise ValueError(f"Unknown address type for address {addr}")


def btc_b58_to_int(x):
    return base58.b58decode_int(x)


def b58addrtoint(addr_str):
    temp: int = btc_b58_to_int(addr_str)
    temp_hex: str = strip_leading_0x(hex(temp))
    if len(temp_hex) % 2 == 1:
        temp_hex = '0' + temp_hex
    temp_bytes: bytearray = bytearray.fromhex(temp_hex)
    temp_bytes = temp_bytes[:-4]  # Always chop off the last 4 bytes
    if len(temp_bytes) > 20:
        assert len(
            temp_bytes) == 21, f"After chopping off the last 4 bytes (checksum) from a b58 btc addr (P2PKH or P2SH) - expect at most 21 bytes remaining. Got {len(temp_bytes)} bytes"
        # If the address is longer than 20 bytes, chop off the first bytes
        temp_bytes = temp_bytes[-20:]
    result = int.from_bytes(temp_bytes, byteorder='big')
    assert result < 2**160, f"ERROR in b58addrtoint {addr_str} because result is {result} which is larger than 2**160"
    return result


def bech32CharToInt(c):
    if c not in BECH32_CHARSET:
        raise Exception(f"{c} not in BECH32_CHARSET")
    return BECH32_CHARSET.index(c)


def convertbits(data, frombits, tobits, pad=True):
    """
    'General power-of-2 base conversion'

    Source: https://github.com/sipa/bech32/tree/master/ref/python

    :param data: Data values to convert
    :type data: list
    :param frombits: Number of bits in source data
    :type frombits: int
    :param tobits: Number of bits in result data
    :type tobits: int
    :param pad: Use padding zero's or not. Default is True
    :type pad: bool

    :return list: Converted values
    """
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def bech32addrtoint(addr_str):
    '''
    This address must be either 42 chars long (P2WPKH) or 62 chars long (P2WSH)
    The important component of it is the first 160/256 bits after the bc1<witness_version_bechbyte> 4 char prefix
    '''
    assert len(addr_str) == 42 or len(
        addr_str) == 62, f"Expected bech32addrstring to be 42 bech32-characters exactly. Got {len(addr_str)}"
    assert addr_str.lower() == addr_str or addr_str.upper == addr_str, "mismatch in lower/upper case not allowed in bech32 addr"
    addr_str = addr_str.lower()
    assert addr_str[:3] == "bc1"
    temp = 0
    important_addr_substr = addr_str[4:-6]
    experiment = []
    for c in important_addr_substr:
        experiment.append(bech32CharToInt(c))
    decoded: list[int] = convertbits(experiment, 5, 8, False)
    for i in range(len(decoded)):
        temp = temp + decoded[len(decoded) - 1 - i] * (256 ** i)
    temp_hexstr = strip_leading_0x(hex(temp))
    result = int(temp_hexstr, 16)
    assert result < 2 ** 256, f"result is {result} and should be less than 2**256. addr_str was {addr_str} with length {len(addr_str)}, \
        with prefix, separator, witver ... checksum removed is {important_addr_substr} with length {len(important_addr_substr)}"
    assert result > 0, f"result is {result} and should be greater than 0. addr_str was {addr_str} with length {len(addr_str)}"
    return result


def btc_addr_to_int(addr: str) -> int:
    """
    Returns the hash part of the BTC address as an integer
    For correctness of proving ownership of an address, the hash part of the BTC address is the only part that matters
    """
    addr_type = get_btc_address_type(addr)
    if addr_type == BitcoinAddressType.P2PKH or addr_type == BitcoinAddressType.P2SH:
        return b58addrtoint(addr)
    elif addr_type == BitcoinAddressType.P2WPKH or addr_type == BitcoinAddressType.P2WSH:
        return bech32addrtoint(addr)
    else:
        raise ValueError(f"Unknown address type for address {addr}")
