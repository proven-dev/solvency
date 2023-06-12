"""
ZK-Proof of Solvency consists of two parts. Assets and Liabilities. Ultimately it proves that Assets >= Liabilities for each token.

At a high level, the Assets side works as follows:
- The prover inputs a list of public addresses and their balances (called an anonymity set)
- The prover claims they own a certain subset of these public addresses
- The prover proves these claims inside the ZK-SNARK

In order to be confident that no cheating took place on the assets side, a verifier must check (among other things) the validity of the used anonymity sets.
The prover will publicly share "Here are the Snapshots I used in my Proof of Assets!" to which the verifier must check that the addresses and balances in these snapshots look correct.
Then the verifier must also check that these snapshots are indeed the ones the prover used. This is done by hashing the snapshots and comparing the hash to the one the prover shared
in their revealed public outputs.

The hash function used here is called Poseidon Hash. It is canonical to use this hash function in ZK-SNARKs because it is very efficient to compute inside the SNARK.
"""

from dataclasses import dataclass
from enum import Enum
from utils.btc_utils import btc_addr_to_int

from utils.common import BALANCE_DIMENSION, get_balance_orders
from utils.poseidon.poseidon_hash import linear_hash_many, poseidon_hash
from utils.scaling import snapshot_precision_to_proof_precision

VERBOSE = True


def print_verbose(x: str):
    if VERBOSE:
        print(x)


@dataclass
class PublicAddressInfo:
    address: str
    balances: list[int]


class AnonsetType(Enum):
    BTC_PUBKEY = 0
    BTC_SCRIPT = 1
    ETH = 2


def make_address_integer_regs(address: str, anonset_type: AnonsetType) -> list[int]:
    if anonset_type == AnonsetType.BTC_PUBKEY:
        addr_int = btc_addr_to_int(address)
        assert addr_int < 2 ** 200, f"ERROR: BTC pubkey address {address} is too large as an integer: {addr_int}."
        return [addr_int]
    elif anonset_type == AnonsetType.BTC_SCRIPT:
        # The important part of a BTC Script Hash Address is 256 bits, which does not fit into a single
        # BN254 (or BLS12-381) field element. So we split it into two 128-bit field elements.
        addr_int = btc_addr_to_int(address)
        assert addr_int < 2 ** 256, f"ERROR: BTC script address {address} is too large as an integer: {addr_int}."
        regs: list[int] = []
        for _ in range(2):
            reg = addr_int % (2 ** 128)
            regs.append(reg)
            addr_int = addr_int // (2 ** 128)
        return regs
    elif anonset_type == AnonsetType.ETH:
        addr_int = int(address, 16)
        assert addr_int < 2 ** 200, f"ERROR: ETH address {address} is too large as an integer: {addr_int}."
        return [addr_int]
    else:
        raise Exception(
            f"ERROR: Unknown or Unsupported anonset_type {anonset_type}. Should be BTC_PUBKEY or BTC_SCRIPT or ETH")


def get_anonset_hash(anonset: list[PublicAddressInfo], anonset_type: AnonsetType, npubaddrs: int, balanceDimension: int = BALANCE_DIMENSION) -> int:
    print_verbose(
        f"Inside get_anonset_hash. anonset length: {len(anonset)} anonset_type: {anonset_type} npubaddrs: {npubaddrs} balanceDimension: {balanceDimension}")

    assert len(
        anonset) == npubaddrs, f"ERROR: Anonset length {len(anonset)} does not match expected length {npubaddrs}."

    # Step 1 hash anonset balances
    balance_orders: list[str] = get_balance_orders()
    anonset_balances: list[int] = []
    for ii in range(npubaddrs):
        public_address_info: PublicAddressInfo = anonset[ii]
        for jj in range(balanceDimension):
            which_token: str = balance_orders[jj]
            snapshot_balance: int = public_address_info.balances[jj]
            proof_balance: int = snapshot_precision_to_proof_precision(
                which_token, snapshot_balance)
            anonset_balances.append(proof_balance)
    balances_hash: int = linear_hash_many(anonset_balances)

    print_verbose(f"balances_hash: {balances_hash}")

    # Step 2 hash anonset addresses
    anonset_addresses: list[list[int]] = []
    address_len = None
    for ii in range(npubaddrs):
        address_int_regs: list[int] = make_address_integer_regs(
            anonset[ii].address, anonset_type)
        anonset_addresses.append(address_int_regs)
    flatted_anonset_addrs: list[int] = []
    for ii in range(npubaddrs):
        for jj in range(address_len):
            flatted_anonset_addrs.append(anonset_addresses[ii][jj])
    addrs_hash: int = linear_hash_many(flatted_anonset_addrs)
    print_verbose(f"addrs_hash: {addrs_hash}")

    # Step 3 hash the (balances_hash, addrs_hash) together
    result: int = poseidon_hash([balances_hash, addrs_hash], 2)
    print_verbose(f"result: {result}")
    return result
