import pickle
import os
from tqdm import tqdm

# Custom modules for encryption/decryption and querying the ciphertext
from task3_client import query_server
from task2_des import des_encrypt, des_decrypt, convert_to_binary, generate_subkeys

# This function ensures each 8-bit byte of the 64-bit key has odd parity.
def add_des_parity_bits(key56_bin_str):
    if len(key56_bin_str) != 56:
        raise ValueError("Input to add_des_parity_bits must be a 56-bit binary string.")
    key64_bin = ""
    for i in range(0, 56, 7):
        byte_7bits = key56_bin_str[i:i+7]
        ones_count = byte_7bits.count('1')
        # Set parity bit to '1' if ones_count is even, '0' if ones_count is odd, to make total odd.
        parity_bit = '1' if ones_count % 2 == 0 else '0'
        key64_bin += byte_7bits + parity_bit
    return key64_bin

# Forward phase of Meet-in-the-Middle (MITM) attack
def forward_mitm(plaintext_hex, checkpoint_file="checkpoint.pkl"):
    table = {}
    start_key1_val = 0

    if os.path.exists(checkpoint_file):
        print("Resuming from checkpoint...")
        try:
            with open(checkpoint_file, "rb") as f:
                checkpoint = pickle.load(f)
                # Ensure checkpoint has the expected keys
                if "last_key1_val" in checkpoint and "table" in checkpoint:
                    start_key1_val = checkpoint["last_key1_val"]
                    table = checkpoint["table"]
                    print(f"Resuming with key1_val = {start_key1_val} and table size = {len(table)}")
                else:
                    print("Checkpoint file format error. Starting fresh.")
        except (pickle.UnpicklingError, EOFError, KeyError) as e:
            print(f"Error loading checkpoint: {e}. Starting fresh.")
            # Reset in case of error
            start_key1_val = 0
            table = {}


    if start_key1_val == 4096: # All key1 values processed
        print("Forward table already complete based on checkpoint.")
        return table
    
    print(f"Building MITM table from key1_val = {start_key1_val}...")
    pt_bin = convert_to_binary(plaintext_hex, 64)

    for key1_val in tqdm(range(start_key1_val, 4096), desc="Forward Phase Progress", initial=start_key1_val, total=4096):
        key1_hex = format(key1_val, '03x') + '00000000000' # Puts 12 bits at LSB of first 3 hex, rest zero
        key1_hex = key1_hex[-14:]
        key1_hex = format(key1_val, '014x') # This puts 0-FFF in the 12 LSBs of the 14 hex digits

        key1_bin_56 = convert_to_binary(key1_hex, 56)
        key1_bin_64 = add_des_parity_bits(key1_bin_56)
        subkeys1 = generate_subkeys(key1_bin_64)
        
        encrypted_m1_bin = des_encrypt(pt_bin, subkeys1) # M1 = Enc(K1, P)

        for key2_val in range(4096): # Inner loop for K2
            key2_hex = format(key2_val, '014x')
            key2_bin_56 = convert_to_binary(key2_hex, 56)
            key2_bin_64 = add_des_parity_bits(key2_bin_56)
            subkeys2 = generate_subkeys(key2_bin_64)
            
            # M2 = Dec(K2, M1)
            intermediate_m2_bin = des_decrypt(encrypted_m1_bin, subkeys2)
            intermediate_m2_hex = hex(int(intermediate_m2_bin, 2))[2:].zfill(16).upper()
            
            table[intermediate_m2_hex] = (key1_hex, key2_hex) # Store M2 -> (K1_hex, K2_hex)

        if (key1_val + 1) % 128 == 0 or key1_val == 4095: # Save checkpoint periodically or at the end
            with open(checkpoint_file, "wb") as f:
                pickle.dump({
                    "last_key1_val": key1_val + 1,
                    "table": table
                }, f)
            # print(f"Checkpoint saved at key1_val = {key1_val}")

    print("MITM forward table completed.")
    return table

# Backward phase of MITM attack
def backward_mitm(ciphertext_hex, table):
    print("Starting backward MITM search...")
    ct_bin = convert_to_binary(ciphertext_hex, 64)

    for k1c_val in tqdm(range(4096), desc="Backward Phase Progress"): # This K1 is for the third DES op
        k1c_hex = format(k1c_val, '014x') 
        k1c_bin_56 = convert_to_binary(k1c_hex, 56)
        k1c_bin_64 = add_des_parity_bits(k1c_bin_56)
        k1c_subkeys = generate_subkeys(k1c_bin_64)

        # M2_prime = Dec(K1c, C)
        decrypted_m2_prime_bin = des_decrypt(ct_bin, k1c_subkeys)
        decrypted_m2_prime_hex = hex(int(decrypted_m2_prime_bin, 2))[2:].zfill(16).upper()

        if decrypted_m2_prime_hex in table:
            # Retrieved K1f (from first Enc) and K2f (from Dec) from the forward table
            forward_k1f_hex, forward_k2f_hex = table[decrypted_m2_prime_hex]
            
            # For C = Enc(K1, Dec(K2, Enc(K1, P))),
            # K1c (k1c_hex) must match K1f (forward_k1f_hex)
            if k1c_hex == forward_k1f_hex:
                print(f"\nPotential match found!")
                print(f"  K1 (from backward, for Enc_3): {k1c_hex}")
                print(f"  K1 (from forward, for Enc_1): {forward_k1f_hex}")
                print(f"  K2 (from forward, for Dec_2): {forward_k2f_hex}")
                return k1c_hex, forward_k2f_hex # K1=k1c_hex, K2=forward_k2f_hex

    print("No match found after backward search.")
    return None, None


def convert_56bit_hex_to_64bit_hex_with_parity(key56_hex): # Renamed for clarity
    """Converts 14-digit hex key (56-bit effective) to full 16-digit hex key (64-bit with parity)."""
    key56_bin = convert_to_binary(key56_hex, 56)
    key64_bin = add_des_parity_bits(key56_bin)
    key64_hex = hex(int(key64_bin, 2))[2:].zfill(16).upper()
    return key64_hex

# Main routine to execute the attack
if __name__ == "__main__":
    student_id = "1220619" # Replace with your actual student ID for querying
    plaintext = "0123456789ABCDEF" # Known plaintext

    # Get ciphertext from server using known plaintext
    print(f"Querying server for ciphertext with PT: {plaintext} and ID: {student_id}")
    try:
        ciphertext = query_server(student_id, plaintext)
        print(f"Ciphertext from server: {ciphertext}")
    except ValueError as e:
        print(f"Error querying server: {e}")
        exit()
    except Exception as e: # Catch other potential request errors
        print(f"An unexpected error occurred while querying server: {e}")
        exit()
    
    # Build forward MITM table
    # Checkpoint file will be named based on plaintext for uniqueness if multiple PTs are tested
    checkpoint_filename = f"checkpoint_pt_{plaintext}.pkl"
    table = forward_mitm(plaintext, checkpoint_file=checkpoint_filename)
    print("Forward MITM table built.")
    print(f"Table size: {len(table)}")
    
    if not table:
        print("Forward MITM table is empty. Attack cannot proceed.")
        exit()

    # Try to recover the keys using backward MITM search
    recovered_k1_56hex, recovered_k2_56hex = backward_mitm(ciphertext, table)

    # Output the results
    if recovered_k1_56hex and recovered_k2_56hex:
        print("\n--- Keys Potentially Recovered! ---")
        print(f"Recovered K1 (56-bit effective, 14-hex): {recovered_k1_56hex}")
        print(f"Recovered K2 (56-bit effective, 14-hex): {recovered_k2_56hex}")

        # Convert to 64-bit DES keys with parity bits for final presentation
        k1_full_64hex = convert_56bit_hex_to_64bit_hex_with_parity(recovered_k1_56hex)
        k2_full_64hex = convert_56bit_hex_to_64bit_hex_with_parity(recovered_k2_56hex)

        print(f"K1 (full 64-bit DES key, 16-hex): {k1_full_64hex}")
        print(f"K2 (full 64-bit DES key, 16-hex): {k2_full_64hex}")
        
        print("\n--- Verification (using recovered keys) ---")
        pt_bin_verify = convert_to_binary(plaintext, 64)
        
        k1_bin_64_verify = add_des_parity_bits(convert_to_binary(recovered_k1_56hex, 56))
        k2_bin_64_verify = add_des_parity_bits(convert_to_binary(recovered_k2_56hex, 56))

        subkeys_k1_verify = generate_subkeys(k1_bin_64_verify)
        subkeys_k2_verify = generate_subkeys(k2_bin_64_verify)

        # C = Enc(K1, Dec(K2, Enc(K1, P)))
        m1_verify = des_encrypt(pt_bin_verify, subkeys_k1_verify)
        m2_verify = des_decrypt(m1_verify, subkeys_k2_verify)
        ct_verify_bin = des_encrypt(m2_verify, subkeys_k1_verify)
        ct_verify_hex = hex(int(ct_verify_bin, 2))[2:].zfill(16).upper()

        print(f"Plaintext for verification: {plaintext}")
        print(f"Original Ciphertext from server: {ciphertext}")
        print(f"Ciphertext re-computed with recovered keys: {ct_verify_hex}")
        if ct_verify_hex == ciphertext:
            print("SUCCESS: Re-computed ciphertext matches the original ciphertext from the server!")
        else:
            print("ERROR: Re-computed ciphertext DOES NOT match the original. Keys might be incorrect or a bug exists.")

    else:
        print("\nAttack failed. Keys were not recovered.")