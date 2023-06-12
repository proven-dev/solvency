BALANCE_DIMENSION = 18
BITCOIN_TOKEN = "BTC"
ETHER_TOKEN = "ETH"
SUPPORTED_TOKENS = [BITCOIN_TOKEN, ETHER_TOKEN]
assert BALANCE_DIMENSION >= len(SUPPORTED_TOKENS)
FIELD_SCALAR_BITS = 254

# As of Today, only BTC and ETH are supported, however we have reserved space for 16 more tokens


def get_balance_orders(balance_dimension=BALANCE_DIMENSION):
    return SUPPORTED_TOKENS + [f"Unsupported-Index-{i}" for i in range(balance_dimension - len(SUPPORTED_TOKENS))]


# Token -> Precision Dicts, if item not in dict, assume precision is 1
ACCT_PRECISION_DICT = {
    BITCOIN_TOKEN: 8,
    ETHER_TOKEN: 18,
}

PROOF_PRECISION_DICT = {
    BITCOIN_TOKEN: 8,
    ETHER_TOKEN: 7,
}

SNAPSHOT_PRECISION_DICT = {
    BITCOIN_TOKEN: 8,
    ETHER_TOKEN: 18,
}


def strip_leading_0x(s):
    if len(s) >= 2 and s[0] == "0" and s[1] == "x":
        return s[2:]
    return s


def split_into_chunks(all_elts, chunk_size: int, fill_empty=None):
    start_idx = 0
    len_elts = len(all_elts)
    res = []
    while start_idx < len_elts:
        end_idx = start_idx + chunk_size
        if end_idx > len_elts:
            curr_chunk = all_elts[start_idx:len_elts]
            if fill_empty is not None:
                for _ in range(end_idx-len_elts):
                    new_elt = fill_empty()
                    curr_chunk.append(new_elt)
            res.append(curr_chunk)
        else:
            res.append(all_elts[start_idx:end_idx])
        start_idx += chunk_size
    return res


def int_to_bin(x_int, expected_length=None, round_to_eight=False):
    x_bin = bin(x_int)[2:]
    if expected_length:
        padded_zeros = expected_length - len(x_bin)
        assert padded_zeros >= 0
        return "0" * padded_zeros + x_bin
    elif round_to_eight:
        while (len(x_bin) % 8 != 0):
            x_bin = "0" + x_bin
    return x_bin

# least sig register first


def int_to_regs(x):
    """
    Given an integer x < 2^256, return a list of 4 registers of 64 bits each
    """
    # 4 registers of 64 bits each
    regs = []
    temp = x
    for _ in range(4):
        reg = temp % (2 ** 64)
        regs.append(str(reg))
        temp = temp // (2 ** 64)
    assert temp == 0, f"x={x} was larger than 2^256 error"
    return regs
