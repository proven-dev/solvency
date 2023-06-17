
# Poseidon-128 for BN254
from .poseidon_consts import get_RP, get_mds, get_round_constants


def s_box(x):
    p = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
    a = (x * x) % p
    b = (a * a) % p
    return (x * b) % p


def dotprod(a, b):
    p = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001

    assert (len(a) == len(b))
    res = 0
    for i in range(len(a)):
        res += ((a[i] * b[i]) % p)
    return res % p

# REQ M is square


def matrix_multiply(M, x):
    b = []
    assert len(M) == len(M[0])
    assert len(M) == len(x)
    for i in range(len(x)):
        b.append(dotprod(M[i], x))
    return b

# Includes the domain separation element


def perm(input_words, t):
    p = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001

    assert (len(input_words) == t)
    RP = get_RP(t)
    Rf = 4
    M = get_mds(t)
    RC = get_round_constants(t)
    state_words = list(input_words)

    rc_counter = 0
    # First full rounds
    for r in range(Rf):
        # Round constants, nonlinear layer, matrix multiplication
        for i in range(t):
            state_words[i] = (state_words[i] + RC[rc_counter]) % p
            rc_counter += 1
        for i in range(t):
            state_words[i] = s_box(state_words[i])
        state_words = matrix_multiply(M, state_words)

    # Middle partial rounds
    for r in range(RP):
        # Round constants, nonlinear layer, matrix multiplication
        for i in range(t):
            state_words[i] = (state_words[i] + RC[rc_counter]) % p
            rc_counter += 1
        state_words[0] = s_box(state_words[0])
        state_words = matrix_multiply(M, state_words)
    # Last full rounds
    for r in range(Rf):
        # Round constants, nonlinear layer, matrix multiplication
        for i in range(t):
            state_words[i] = (state_words[i] + RC[rc_counter]) % p
            rc_counter += 1
        for i in range(t):
            state_words[i] = s_box(state_words[i])
        state_words = matrix_multiply(M, state_words)
    assert rc_counter == len(RC)
    return state_words


def poseidon_hash(input: list[int], arity: int) -> int:
    assert len(
        input) == arity, f"The length of the input {input} must be equal to the arity {arity}. Got len input = {len(input)} and arity = {arity}"
    copied_input = input.copy()
    # maybe should be different for domain separation
    state = [0] + copied_input
    output = perm(state, arity+1)
    return output[0]


def linear_hash_many(inputs, arity=16):
    # base case
    if len(inputs) <= arity:
        base_hash_inputs = inputs + [0] * (arity - len(inputs))
        current_hash = poseidon_hash(base_hash_inputs, arity)
        remaining_inputs = []
    else:
        base_hash_inputs = inputs[0:arity]
        remaining_inputs = inputs[arity:]
        current_hash = poseidon_hash(base_hash_inputs, arity)

    while len(remaining_inputs) > 0:
        if len(remaining_inputs) <= arity - 1:
            hash_inputs = [current_hash] + remaining_inputs + \
                [0] * (arity - len(remaining_inputs) - 1)
            remaining_inputs = []
            current_hash = poseidon_hash(hash_inputs, arity)
        else:
            hash_inputs = [current_hash] + remaining_inputs[0:arity-1]
            remaining_inputs = remaining_inputs[arity-1:]
            current_hash = poseidon_hash(hash_inputs, arity)

    return current_hash


def testA():
    res = perm([0, 0, 0], 3)
    # Gives this output, which lines up with: https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/poseidonperm_x5_254_3.sage
    # [14744269619966411208579211824598458697587494354926760081771325075741142829156,
    # 30774197328305950657673617643185548007133594607493575680960748512578280791430,
    # 46826558071237419519270219508968739415572685149512873732126208348441235559554]
    print(res)
