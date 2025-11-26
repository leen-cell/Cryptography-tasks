from task2_des import *

def bin_to_hex(bin_str):
    return hex(int(bin_str, 2))[2:].zfill(len(bin_str) // 4).upper()

def count_bit_diff(bin1, bin2):
    return sum(b1 != b2 for b1, b2 in zip(bin1, bin2))

def main():
    mode = input("Select operation - Encrypt (E) or Decrypt (D): ").strip().upper()
    if mode not in ['E', 'D']:
        print("Invalid mode. Choose E or D.")
        return

    message_hex = input("Enter 64-bit hexadecimal plaintext or ciphertext: ").strip()
    key_hex = input("Enter 64-bit hexadecimal key: ").strip()

    if len(message_hex) != 16 or len(key_hex) != 16:
        print("Invalid input lengths. Plaintext/ciphertext must be 64 bits (16 hex chars), key must be 64 bits (16 hex chars).")
        return

    message_bin = convert_to_binary(message_hex, 64)
    key_bin = convert_to_binary(key_hex, 64)
    key_schedule = generate_subkeys(key_bin)

    if mode == 'E':
        result_bin = des_encrypt(message_bin, key_schedule)
        result_hex = bin_to_hex(result_bin)
        print("Ciphertext (Hex) :", result_hex)


    else:
        result_bin = des_decrypt(message_bin, key_schedule)
        result_hex = bin_to_hex(result_bin)
    
        print("Plaintext (Hex) :", result_hex)


if __name__ == "__main__":
    main()
