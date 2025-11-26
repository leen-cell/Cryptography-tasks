from collections import defaultdict

#this function is to read the input cipher text
def read_ciphertexts_from_file(filename):
    ciphertexts = []
    with open(filename, 'r') as file:
        for line in file:
            hex_str = line.strip()
            if not hex_str or not all(c in '0123456789abcdefABCDEF' for c in hex_str):
                continue
            try:
                ciphertexts.append(bytes.fromhex(hex_str))
            except ValueError:
                continue
    return ciphertexts

#bitwise XOR
def xor_bytes(b1, b2):

    return bytes([a ^ b for a, b in zip(b1, b2)])


def xor_to_text(b1, b2):
    xored = xor_bytes(b1, b2)
    return ''.join([chr(b) if chr(b).isalpha() and chr(b).isascii() else '.' for b in xored])

#write to the file and get all xored values
def write_all_xor_comparisons(ciphertexts, output_filename="xorOutput.txt"):
    xored_list = []
    with open(output_filename, 'w', encoding='utf-8') as out:
        n = len(ciphertexts)
        for i in range(n):
            for j in range(i + 1, n):
                out.write(f"=== XOR between C{i+1} and C{j+1} ===\n")
                out.write(xor_to_text(ciphertexts[i], ciphertexts[j]) + "\n\n")
               # print(xor_to_text(ciphertexts[i], ciphertexts[j]) + "\n\n")
                xored_list.append(xor_to_text(ciphertexts[i], ciphertexts[j]))
    print(f"XOR results written to {output_filename}")
    print(f"Xored results: {xored_list}")
    return xored_list

#find the spaces in the original plaintexts if the xor result is a number then there is a space in that place in one of the ciphers
def find_spaces(xored_list):
    spaces_list = []

    for xored in xored_list:
        spaces_string = []
        for char in xored:
            if char.isalpha():
                #there is a space
                spaces_string.append(" ")
            else:
                #there is letters
                spaces_string.append("*")
        spaces_list.append(''.join(spaces_string))

    return spaces_list


#xoring any letter with space will toggle the case of the letter so one plain originally has a space in that place and the other has a letter

def letters_in_plaintext(ciphertexts, xored_list, num_ciphertexts=10):
    space_guesses = spaces_in_plaintext(xored_list, num_ciphertexts)
    max_len = max(len(c) for c in ciphertexts)
    guesses = [['.'] * max_len for _ in range(num_ciphertexts)]

    for i in range(num_ciphertexts):
        for j in range(i + 1, num_ciphertexts):
            xor_result = xor_bytes(ciphertexts[i], ciphertexts[j])
            for k in range(min(len(xor_result), len(space_guesses[i]), len(space_guesses[j]))):
                if space_guesses[i][k] == '^':
                    guess_char = xor_result[k] ^ 0x20
                    if chr(guess_char).isalpha():  # ONLY accept alphabetic letters
                        guesses[j][k] = chr(guess_char)
                        guesses[i][k] = " "
                elif space_guesses[j][k] == '^':
                    guess_char = xor_result[k] ^ 0x20
                    if chr(guess_char).isalpha():
                        guesses[i][k] = chr(guess_char)
                        guesses[j][k] = " "
    guessed_strings = [''.join(line) for line in guesses]
    for i, g in enumerate(guessed_strings):
        print(f"Guessed P{i+1}: {g}")
    return guessed_strings


#this is the function that guesses the spaces places based on the letters places in the xored ciphers
def spaces_in_plaintext(xored_list, num_ciphertexts = 10):
    #each XORed line is corresponding to a pair (c1,c2), (c1,c2)....
    spaces_list = find_spaces(xored_list)
    max_len = max(len(line) for line in spaces_list)
    votes = [[0] * max_len for _ in range(num_ciphertexts)]
    idx = 0
    for i in range(num_ciphertexts):
        for j in range(i+1,num_ciphertexts):
            space_line = spaces_list[idx]
            for k, char in enumerate(space_line):
                if char == " ":
                    votes[i][k] += 1
                    votes[j][k] += 1
            idx += 1

    threshold = (num_ciphertexts // 2)
    space_guesses = []
    for i in range(num_ciphertexts):
        output = ''
        for count in votes[i]:
            if count >= threshold:
                output += '^'
            else:
                output += '.'
        print(f"Likely a space in P{i+1}: {output}")
        space_guesses.append(output)

    return space_guesses
#finds the keystream (most parts of it)
def key_stream (ciphertexts, guessed_plaintexts):
    max_len = max(len(c) for c in ciphertexts)
    keystream = [None] * max_len

    for i, guessed in enumerate(guessed_plaintexts):
        for k in range(min(len(ciphertexts[i]), len(guessed))):
            char = guessed[k]
            if char != '.':
                keystream[k] = ciphertexts[i][k] ^ ord(char)

    return keystream

def read_target_ciphertext(filename):
    with open(filename, 'r') as f:
        content = f.read()
        # remove label if exists like "Target Ciphertext:"
        content = content.strip().split(':')[-1].strip()
        return bytes.fromhex(content)

if __name__ == "__main__":
    filename = "C:/Users/User/PycharmProjects/cryptoHW1/input.txt"
    ciphertexts = read_ciphertexts_from_file(filename)

    print(f"Loaded {len(ciphertexts)} ciphertexts.\n")
    xored_list = write_all_xor_comparisons(ciphertexts)
    spaces_in_plaintext(xored_list)
    guessed_plaintext=letters_in_plaintext(ciphertexts, xored_list)
    print(guessed_plaintext)
    print(key_stream(ciphertexts, guessed_plaintext))
    #this part should be moved into a function and the target should be read from a file ...
    target_filename = "C:/Users/User/PycharmProjects/cryptoHW1/target"
    target_bytes = read_target_ciphertext(target_filename)

    recovered_keystream = key_stream(ciphertexts, guessed_plaintext)

    decrypted_target = "".join(
        chr(c ^ k) if k is not None and chr(c ^ k).isascii() and chr(c ^ k).isprintable() else '.'
        for c, k in zip(target_bytes, recovered_keystream)
    )

    print("\nDecrypted target message:\n", decrypted_target)