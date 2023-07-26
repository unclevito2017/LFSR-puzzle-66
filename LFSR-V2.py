import hashlib
import base58
import random

class LFSR:
    def __init__(self, seed, taps):
        self.register = list(map(int, seed))
        self.taps = taps

    def shift(self, num_shifts):
        for _ in range(num_shifts):
            feedback = self.register[self.taps[0]]
            for bit in self.taps[1:]:
                feedback ^= self.register[bit]
            self.register.pop()
            self.register.insert(0, feedback)

    def generate_private_key(self):
        return int(''.join(map(str, self.register)), 2)

def hash160(data):
    h = hashlib.new('ripemd160')
    h.update(data)
    return h.digest()

def base58check(data):
    return base58.b58encode_check(data)

def main():
    # The desired public address provided in the challenge
    desired_public_address = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"
    
    base_binary_65 = "0000000110101000000111001011000100110101000000101100100110100001100111"

    taps = [64, 63, 61, 60]  
    lfsr = LFSR(base_binary_65, taps)

    lower_bound = 0
    upper_bound = 2 ** 66  # 2 raised to the power of 66

    while True:
       
        private_key = random.randint(lower_bound, upper_bound)
    
        binary_str = bin(private_key)[2:].zfill(66)
        bitcoin_address = generate_bitcoin_address(private_key)

        if bitcoin_address == desired_public_address:
            print("Found matching private key:", private_key)
            break

    print("Private key not found in the keyspace.")

if __name__ == "__main__":
    main()

    for shift in range(-2, 3):
        shifted_binary = format(base_int_65 << max(0, shift), '066b')
        lfsr_65 = LFSR(shifted_binary, [0, 1, 2, 3, 4, 7, 8, 32, 47, 56, 57, 63, 64, 79, 95, 106, 124, 125, 156, 159, 160, 161, 162, 168, 176, 183, 184, 191, 219, 220, 224, 236, 243, 255])

    if count % 100000 == 0:
        print(f"Progress (Keyspace 66): {count}/{upper_bound}")

if not found_match:
    print("Matching private key not found within the specified range.")
