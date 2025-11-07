from math import comb, log2, ceil, floor

LOG_LIFETIME = 32
RANDOMNESS_FIELD_ELEMENTS = 5
FIELD_ELEMENTS_PER_DIGESTS = 5
BYTES_PER_FIELD_ELEMENT = 31 / 8


def analyse_trivial_encoding(log_w, v, d):
    w = 2**log_w
    z = 24 / log_w
    hypercube_size = w**v
    number_of_possible_encodings = count_tuples(w, v, d)
    avg_signer_grinding = round(
        (hypercube_size) / number_of_possible_encodings)
    security_bits_loss_due_to_non_uniformity = ceil(
        log2((127/126)**ceil(v / (2*z))))
    resulting_security = floor(log2(hypercube_size)) - \
        security_bits_loss_due_to_non_uniformity
    signature_size = ((v + LOG_LIFETIME) *
                      FIELD_ELEMENTS_PER_DIGESTS + RANDOMNESS_FIELD_ELEMENTS) * BYTES_PER_FIELD_ELEMENT
    num_hashes_per_signature = d + floor(v / 2) + LOG_LIFETIME

    print(f"Parameters: w={w}, v={v}, d={d}")
    print(
        f"Number of possible encodings: 2^{(log2(number_of_possible_encodings)):.1f}")
    print(f"Average signer grinding steps: {avg_signer_grinding}")
    print(
        f"Security loss due to non-uniformity: {security_bits_loss_due_to_non_uniformity} bits")
    print(f"Resulting security: {resulting_security} bits")
    print(f"Signature size: {(signature_size / 1024):.2f} KB")
    print(f"Number of hashes to verify a signature: {num_hashes_per_signature}")
    print("")


def count_tuples(w, v, d):
    """
    Count the number of integer tuples (x1, x2, ..., xv)
    with 0 <= xi < w and x1 + ... + xv = d.
    """
    if d < 0 or d >= v * w:
        assert False, "Invalid parameters"

    total = 0
    for k in range(0, v + 1):
        term = d - k * w
        if term < 0:
            break
        total += (-1)**k * comb(v, k) * comb(term + v - 1, v - 1)
    return total


if __name__ == "__main__":
    analyse_trivial_encoding(log_w=2, v=68, d=85)
    analyse_trivial_encoding(log_w=3, v=45, d=130)
