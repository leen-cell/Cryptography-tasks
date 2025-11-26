def convert_to_binary(in_hexa, bits=None):
    bit_length = bits if bits else len(in_hexa) * 4
    return bin(int(in_hexa, 16))[2:].zfill(bit_length)

#standard IP and FP in DES
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

E_BOX_SLIDE = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

S_BOXES = [
    # S1
    [
        [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
        [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
        [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
        [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]
    ],
    # S2
    [
        [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
        [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
        [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
        [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]
    ],
    # S3
    [
        [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
        [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
        [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
        [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]
    ],
    # S4
    [
        [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
        [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
        [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
        [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]
    ],
    # S5
    [
        [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
        [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
        [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
        [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]
    ],
    # S6
    [
        [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
        [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
        [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
        [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]
    ],
    # S7
    [
        [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
        [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
        [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
        [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]
    ],
    # S8
    [
        [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
        [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
        [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
        [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]
    ]
]

P_BOX = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
]

PC1 = [
    # Left half
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    # Right half
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]


PC2 = [
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]


SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

def permute (block,table):
   return ''.join(block[i-1] for i in table)

def initial_permutation(block):
   return permute(block,IP)

def final_permutation(block):
   return permute(block,FP)

def Des_expansion_perm(right_half):
    return permute(right_half,E_BOX_SLIDE)

def split_halfs(block):
    left_half = block[:32]
    right_half = block[32:]
    return [left_half, right_half]

def split_to_sixes(expanded_bits):
    return [expanded_bits[i:i+6] for i in range(0, 48, 6)]

def SBox (expanded_bits):
    splitted = split_to_sixes(expanded_bits)
    sbox_result = ""
    for i in range (8):
        block = splitted[i]
        row = int (block[0]+block[5],2) # from binary to decimal
        col = int(block[1:5], 2)
        val = S_BOXES[i][row][col]
        sbox_result += bin(val)[2:].zfill(4) #remove 0b and padding if needed
    return sbox_result

def PBox (SBox_result):
     return permute(SBox_result,P_BOX)

def left_circular_shift(bits, shift_amount):
    return bits[shift_amount:] + bits[:shift_amount]

def generate_subkeys (key_64bit):
    # Ensure key_64bit is indeed 64 bits long
    if len(key_64bit) != 64:
        raise ValueError("Key for subkey generation must be 64 bits long.")

    key_56bit = ''.join(key_64bit[i - 1] for i in PC1)
    
    L = key_56bit[:28]
    R = key_56bit[28:]
    subkeys = []
    for shift in SHIFT_SCHEDULE:
        # Circular left shift
        L = left_circular_shift(L, shift)
        R = left_circular_shift(R, shift)

        #Combine and apply PC-2
        combined_CD = L + R # This is 56 bits
        # Use the standard PC2 table (that selects 48 bits from 56)
        subkey = ''.join(combined_CD[i - 1] for i in PC2)
        subkeys.append(subkey)

    return subkeys  # List of 16 round keys, each 48 bits

def bitwise_xor(a, b):
    return ''.join('0' if bit_a == bit_b else '1' for bit_a, bit_b in zip(a, b))


def des_encrypt(plaintext_64bit, key_schedule):
    if len(plaintext_64bit) != 64:
        raise ValueError("Plaintext for DES encryption must be 64 bits long.")
    # Initial Permutation
    ip_result = initial_permutation(plaintext_64bit)
    left, right = split_halfs(ip_result)

    #16 DES Rounds
    for round_num in range(16):
        expanded_right = Des_expansion_perm(right)
        xored = bitwise_xor(expanded_right, key_schedule[round_num])
        sbox_output = SBox(xored)  # 32 bits
        pbox_output = PBox(sbox_output)
        new_right = bitwise_xor(pbox_output, left)
        left = right
        right = new_right

    #Final Permutation on (R || L) which becomes (L_16 || R_16) after the loop structure
    combined = right + left # After 16 rounds, 'right' is L_16 and 'left' is R_16. Standard input to FP is L_16 R_16.
    ciphertext = final_permutation(combined)

    return ciphertext

def des_decrypt(ciphertext_64bit, key_schedule):
    if len(ciphertext_64bit) != 64:
        raise ValueError("Ciphertext for DES decryption must be 64 bits long.")
    reversed_keys = key_schedule[::-1]
    return des_encrypt(ciphertext_64bit, reversed_keys)

# This function ensures each 8-bit byte of the 64-bit key has odd parity.
def _add_des_parity_bits_for_main(key56_bin_str):
    if len(key56_bin_str) != 56:
        raise ValueError("Input to _add_des_parity_bits_for_main must be a 56-bit binary string.")
    key64_bin = ""
    for i in range(0, 56, 7):
        byte_7bits = key56_bin_str[i:i+7]
        ones_count = byte_7bits.count('1')
        # Set parity bit to '1' if ones_count is even, '0' if ones_count is odd, to make total odd.
        parity_bit = '1' if ones_count % 2 == 0 else '0'
        key64_bin += byte_7bits + parity_bit
    return key64_bin

if __name__ == "__main__":
   plaintext_hex = "0123456789ABCDEF"
   plaintext_bin = convert_to_binary(plaintext_hex, 64) # Ensure 64 bits

   # Example 56-bit effective key (14 hex characters)
   hex_key_56bit = "133457799BBCDF" # Note: original was 14 chars "133457799BBCD5"
   # Convert to 56-bit binary
   bin_key_56bit = convert_to_binary(hex_key_56bit, 56)
   # Add parity bits to make it a 64-bit binary key
   bin_key_64bit = _add_des_parity_bits_for_main(bin_key_56bit)
   
   print(f"Plaintext (bin): {plaintext_bin}")
   print(f"Key 56bit (hex): {hex_key_56bit}")
   print(f"Key 64bit with parity (bin): {bin_key_64bit}")

   #####key handling
   round_keys = generate_subkeys(bin_key_64bit) # Pass the 64-bit key

   # print(f"Round keys generated: {len(round_keys)} keys")
   # for i, key in enumerate(round_keys):
   #     print(f"Round {i + 1} key: {key} (len: {len(key)})")

  # des rounds
   cipher_bin = des_encrypt(plaintext_bin, round_keys)
   print(f"Ciphertext (hex): {hex(int(cipher_bin, 2))[2:].upper().zfill(16)}")

   decrypted_bin = des_decrypt(cipher_bin, round_keys)
   decrypted_hex = hex(int(decrypted_bin, 2))[2:].upper().zfill(16)
   print(f"Decrypted (hex): {decrypted_hex}")


   print("\n--- Standard Test Vector ---")
   test_pt_hex = "0123456789ABCDEF"
   test_key_hex_64bit = "0123456789ABCDEF" # This is a 64-bit hex key representation
   
   test_pt_bin = convert_to_binary(test_pt_hex, 64)
   test_key_bin_64bit = convert_to_binary(test_key_hex_64bit, 64)

   print(f"Test PT (hex): {test_pt_hex}")
   print(f"Test Key (64-bit hex): {test_key_hex_64bit}")
   
   try:
       test_round_keys = generate_subkeys(test_key_bin_64bit)
       test_cipher_bin = des_encrypt(test_pt_bin, test_round_keys)
       test_cipher_hex = hex(int(test_cipher_bin, 2))[2:].upper().zfill(16)
       print(f"Computed CT (hex): {test_cipher_hex}")
       print(f"Expected CT (hex): 85E813540F0AB405")
       if test_cipher_hex == "85E813540F0AB405":
           print("Test Vector Passed!")
       else:
           print("Test Vector Failed!")
   except Exception as e:
       print(f"Error during test vector processing: {e}")