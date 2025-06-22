from sage.all import *

F.<a> = GF(2^128, modulus=x^128 + x^7 + x^2 + x + 1)
P.<x> = PolynomialRing(F)

# ---------------------------------------------------------------------------------------------------------------------

def convert_to_poly(input):
    """Converts a bytes, str, or SageMath Integer input into a SageMath polynomial"""

    if isinstance(input, str):
        input = bytes.fromhex(input)
    if isinstance(input, Integer):
        input = int(input).to_bytes(16, 'big')

    poly = int.from_bytes(input, 'big')
    poly = int(f"{poly:0128b}"[::-1], 2)
    return F.fetch_int(poly)

# ---------------------------------------------------------------------------------------------------------------------

def poly_to_bytes(input):
    """Converts a SageMath polynomial input into bytes"""

    v = input.integer_representation()
    v = int(f"{v:0128b}"[::-1], 2)
    return v.to_bytes(16, 'big')

# ---------------------------------------------------------------------------------------------------------------------

def to_blocks(data):
    """
    Split data into 16-byte blocks, padded with zeros if necessary, the final block representing the bit length of the data

    Args:
        data[bytes]: The data to be converted to blocks

    Returns:
        blocks (list[bytes]): The resulting blocks formated as a list of bytes
    """

    padded_data = data + b'\x00' * ((-len(data)) % 16)
    blocks = [convert_to_poly(padded_data[i:i+16]) for i in range(0, len(padded_data), 16)]
    bit_len = len(data) * 8
    blocks.append(convert_to_poly(bit_len))

    return blocks

# ---------------------------------------------------------------------------------------------------------------------

def calculate_H_candidates(ciphertexts, tags):
    """
    Computes a polynomial expression for the GHASH whos roots are valid H key candidates

    Args:
        ciphertexts (list[bytes]): 2 ciphertexts from the same key-IV pair for the polynomial to be computed from
        tags (list[poly]): Corresponding list of matching GCM authentication tags

    Returns:
        poly.roots(): The roots of the computed polynomial, which are candidate H values
    """
    
    blocks = []
    for ct in ciphertexts[:2]:
         blocks.append(to_blocks(ct))

    added_blocks = [0] * len(blocks[0])
    for set in blocks:
        for i in range(len(set)):
            added_blocks[i] += set[i]
    poly = sum([added_blocks[i] * x**(len(added_blocks) - i) for i in range(len(added_blocks))])
    
    for tag in tags: poly += tag

    return poly.roots()

# ---------------------------------------------------------------------------------------------------------------------
     
def compute_ghash(ciphertext, H):
    """
    Computes a GHASH for the given ciphertext using the provided H value

    Args:
        ciphertext[bytes]: Ciphertext for the GHASH value to be computed over
        H: H value to be used in the computation

    Returns:
        Q: Computed GHASH value
    """

    Q = F(0)

    for block in to_blocks(ciphertext):
        Q = (Q + block) * H

    return Q

# ---------------------------------------------------------------------------------------------------------------------

def recover_key_values(ciphertexts, tags):
     
    """
    Recovers the H key and Ek(Y0) value used by an AES-GCM key-IV pair based off 3 instances of reuse

    Args:
        ciphertexts (list[bytes]): List of 3 ciphertexts encrypted under the same key and IV
        tags (list[poly]): Corresponding list of matching GCM authentication tags

    Returns:
        A dictonary containing the recovered H and Ek(Y0) values used by the key-IV pair
    """

    candidate_values = calculate_H_candidates(ciphertexts[:2], tags[:2])

    for candidate, _ in candidate_values:

        ghash = compute_ghash(ciphertexts[0], candidate)
        Y = ghash + tags[0]
        calculated_tag = compute_ghash(ciphertexts[2], candidate) + Y

        if calculated_tag == tags[2]:
            return {"H": candidate, "Y": Y}
    
    return None

# ---------------------------------------------------------------------------------------------------------------------

def main():

    choice = input("Input file name to load values from or ('new') for new calculation: ").strip()

    if  choice == 'new':

        ciphertexts = []
        tags = []
        for i in range(1, 4):
            ciphertext = bytes.fromhex(input(f"Enter ciphertext {i} (hex): ").strip())
            tag = convert_to_poly(input(f"Enter tag {i} (hex): ").strip())
            ciphertexts.append(ciphertext)
            tags.append(tag)

        recovered_values = recover_key_values(ciphertexts, tags)
        print(f"\nRecovered H Key: {poly_to_bytes(recovered_values['H']).hex()}")
        print(f"Recovered Y Value: {poly_to_bytes(recovered_values['Y']).hex()}\n")

    else:
        with open(choice, "r") as f:
            loaded_values = eval(f.read())
        recovered_values = {'H': convert_to_poly(loaded_values['H']), 'Y': convert_to_poly(loaded_values['Y'])}


    while True:

        forge = input("Enter ciphertext to forge tag for, ('save FILENAME') to save key values, or ('exit'): ").strip()
        if forge.lower() == 'exit':
            break
        if forge[:4].lower() == 'save':
            if len(forge) < 6:
                print("\nMust include a filename to save keys to\n")
                continue
            save_values = {'H': poly_to_bytes(recovered_values['H']), 'Y': poly_to_bytes(recovered_values['Y'])}
            try:
                with open(forge[5:], "w") as f:
                    f.write(str(save_values))
            except:
                print("Failed to save keys to file")
            continue

        input_ciphertext = bytes.fromhex(forge)
        forged_tag = compute_ghash(input_ciphertext, recovered_values['H']) + recovered_values['Y']
        print(f"\nForged tag: {poly_to_bytes(forged_tag).hex()}\n")

# ---------------------------------------------------------------------------------------------------------------------

main()