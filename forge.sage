from sage.all import *

def recover_GHASH_key(ciphertexts, tags):
     
     """
    Recovers the GHASH key used by AES-GCM with the reused key-IV pair

    Args:
        ciphertexts (list[bytes]): List of ciphertexts encrypted under the same key and IV
        tags (list[bytes]): Corresponding list of GCM authentication tags

    Returns:
        bytes: The recovered GHASH key, or None if recovery fails
    """
     
     print(calcualte_H_list(ciphertexts[:2], tags[:2]))
     
def calcualte_H_list(ciphertexts, tags):
      
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

    print(blocks)

    F.<a> = GF(2)[]
    F.<x> = GF(2^128, modulus=a^128 + a^7 + a^2 + a + 1)
    R.<H> = PolynomialRing(F)
    return (H^2 + H + 1).roots()

def to_blocks(data):
     data = data + b'\x00' * (len(data) % 16)
     return [int.from_bytes(data[i:i+16], 'big') for i in range(0, len(data) - 16, 16)]


ciphertexts = [bytes.fromhex("13885791778d3136a229"), bytes.fromhex("12835c92748e323da928"), bytes.fromhex("138a569c71833239ae2f")]
tags = ["ba476c81cd51b05cf9a43e09233b02c7", "6066e62e9be713da301f70b2513c4f3c", "9b2513c334c92864f1ab2d802503a488"]

recover_GHASH_key(ciphertexts, tags)