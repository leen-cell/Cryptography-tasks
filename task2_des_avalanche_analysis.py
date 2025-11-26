import random
from task2_des import des_encrypt, generate_subkeys

def flip_bit(binary_str, index):
    flipped = list(binary_str)
    flipped[index] = '1' if flipped[index] == '0' else '0'
    return ''.join(flipped)

def count_bit_difference(a, b):
    return sum(bit1 != bit2 for bit1, bit2 in zip(a, b))

def generate_random_binary(bits):
    return ''.join(random.choice('01') for _ in range(bits))

def run_avalanche_analysis():
    results = []

    print("Running Avalanche Effect Analysis (10 trials):\n")
    print("{:<7} {:<15} {:<30}".format("Trial", "Flipped", "Bits Changed in Ciphertext"))
    print("-" * 55)

    for trial in range(1, 11):
        P1 = generate_random_binary(64)
        K1 = generate_random_binary(56)

        round_keys = generate_subkeys(K1)
        C1 = des_encrypt(P1, round_keys)

        # Plaintext flip
        flip_index_p = random.randint(0, 63)
        P1_flipped = flip_bit(P1, flip_index_p)
        C2_plain_flip = des_encrypt(P1_flipped, round_keys)
        diff_plain = count_bit_difference(C1, C2_plain_flip)
        results.append((trial, "Plaintext", diff_plain))
        print("{:<7} {:<15} {:<30}".format(trial, "Plaintext", f"{diff_plain}"))

        # Key flip
        flip_index_k = random.randint(0, 55)
        K1_flipped = flip_bit(K1, flip_index_k)
        round_keys_flipped = generate_subkeys(K1_flipped)
        C2_key_flip = des_encrypt(P1, round_keys_flipped)
        diff_key = count_bit_difference(C1, C2_key_flip)
        results.append((trial, "Key", diff_key))
        print("{:<7} {:<15} {:<30}".format(trial, "Key", f"{diff_key}"))

    print("\nSummary of Avalanche Effect:")
    print(" - A strong avalanche effect means flipping 1 input bit should flip about 32 out of 64 ciphertext bits.")
    print(" - Values significantly lower or exactly 0 may indicate issues in implementation.")
    print(" - DES is designed to have strong avalanche behavior after multiple rounds.\n")

if __name__ == "__main__":
    run_avalanche_analysis()
