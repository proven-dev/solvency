# Given value = 12345 and input_decimals = 2 and output_decimals = 3, make sure to return 123450
# Given value = 123456 and input_decimals = 4 and output_decimals = 1, if round_up then return 124 else return 123
from utils.consts import ACCT_PRECISION_DICT, PROOF_PRECISION_DICT, SNAPSHOT_PRECISION_DICT


def scale_units(value: int, input_decimals: int, output_decimals: int, round_up: bool = True) -> int:
    assert value >= 0, f"In scale_units # value must be non-negative. Got value={value}"
    precision_diff = output_decimals - input_decimals
    if precision_diff >= 0:
        return value * (10 ** precision_diff)
    
    precision_diff = abs(precision_diff)
    new_value = value // (10 ** precision_diff)
    if round_up and new_value * (10 ** precision_diff) != value:
        new_value += 1
    return new_value

def snapshot_precision_to_proof_precision(which_token: str, value: int) -> int:
    if which_token not in SNAPSHOT_PRECISION_DICT or which_token not in PROOF_PRECISION_DICT:
        return value
    return scale_units(value, SNAPSHOT_PRECISION_DICT[which_token], PROOF_PRECISION_DICT[which_token])

def account_precision_to_proof_precision(which_token: str, value: int) -> int:
    if which_token not in ACCT_PRECISION_DICT or which_token not in PROOF_PRECISION_DICT:
        return value
    return scale_units(value, ACCT_PRECISION_DICT[which_token], PROOF_PRECISION_DICT[which_token])