from sage.all import *

# ---------------------------------------------------------------------------------------------------------------------

def to_blocks(data):
     """ Split data into 16-byte blocks, pad with zeros if necessary. """
     pad_len = (16 - (len(data) % 16)) % 16
     padded_data = data + b'\x00' * pad_len
     blocks = [int.from_bytes(padded_data[i:i+16], 'big') for i in range(0, len(padded_data), 16)]
     bit_len = len(data) * 8
     blocks.append(bit_len)
     return blocks

# ---------------------------------------------------------------------------------------------------------------------

def ghash_poly(blocks, tags):
    """Return GHASH polynomial expression coefficients."""

    xored_blocks = [0] * len(blocks[0])
    for set in blocks:
        for i in range(len(set)):
            xored_blocks[i] ^^= set[i]
    block_poly = sum([xored_blocks[i] * var('h')**(len(xored_blocks) - i) for i in range(len(xored_blocks))])
    
    xored_tags = 0
    for i in tags: xored_tags ^^= i

    final_poly = block_poly + xored_tags

    return final_poly

# ---------------------------------------------------------------------------------------------------------------------

def recover_ghash(ciphertexts, tags):
     
    """
    Recovers the GHASH key used by AES-GCM with the reused key-IV pair

    Args:
        ciphertexts (list[bytes]): List of ciphertexts encrypted under the same key and IV, needs 3 values
        tags (list[bytes]): Corresponding list of matching GCM authentication tags

    Returns:
        bytes: The recovered GHASH key, or None if recovery fails
    """
    candidate_values = calcualte_H_candidates(ciphertexts[:2], tags[:2])
    verify_H_candidates(candidate_values, ciphertexts[2], tags[2])

# ---------------------------------------------------------------------------------------------------------------------
     
def calcualte_H_candidates(ciphertexts, tags):
      
    """
    Calculates a list of potential H values based on two ciphertext-tag, sets

    Args:
        ciphertexts (list[bytes]): List of ciphertexts encrypted under the same key and IV
        tags (list[bytes]): Corresponding list of GCM authentication tags

    Returns:
        bytes: A list of potential H values
    """

    blocks = []
    for ct in ciphertexts:
         blocks.append(to_blocks(ct))

    polynomial = ghash_poly(blocks, tags)

    F.<a> = GF(2)[]
    F.<x> = GF(2^128, modulus=a^128 + a^7 + a^2 + a + 1)
    R.<H> = PolynomialRing(F)
    roots = (polynomial).roots()
    return [root for root, _ in roots]

# ---------------------------------------------------------------------------------------------------------------------

def verify_H_candidates(H_candidates, ciphertext, tag):
    for root in H_candidates:
        ghash = compute_ghash(to_blocks(ciphertext), root)
        print(ghash)
    return

# ---------------------------------------------------------------------------------------------------------------------

def compute_ghash(blocks, H):
    """
    Computes GHASH over blocks using H value.

    Args:
        blocks (list[bytes]): List of blocks for the GHASH value to be computed over
        H: H value to be used in the computation

    Returns:
        Y: Computed GHASH value
    """

    F.<a> = GF(2)[]
    F.<x> = GF(2^128)
    R.<H> = PolynomialRing(F)
    Q = F(0)

    # TODO: Make this work
    for block in blocks:
        Q = (Q ^^ block) * H
    return Q

# ---------------------------------------------------------------------------------------------------------------------

ciphertexts = [bytes.fromhex("66501a5d46"), bytes.fromhex("7de32966f792"), bytes.fromhex("138a569c71833239ae2f")]
tags = [int("40975f3152c55989a883aad0339d1cc6", 16), int("f634b6886363dacde6876bbb3384b57a", 16), int("9b2513c334c92864f1ab2d802503a488", 16)]

recover_ghash(ciphertexts, tags)