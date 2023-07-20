import hashlib
import base58

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

desired_public_address = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"
desired_hash160 = bytes.fromhex("20d45a6a762535700ce9e0b216e31994335db8a5")

lower_bound = 0
upper_bound = 2 ** 66  # 2 raised to the power of 66

# Binary values for the beginning and end of keyspace 66
beginning_binary_66 = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000"
end_binary_66 = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000111111111111111111111111111111111111111111111111111111111111111111"

beginning_int_66 = int(beginning_binary_66, 2)
end_int_66 = int(end_binary_66, 2)

lfsr_66 = LFSR(beginning_binary_66, [0, 1, 2, 3, 4, 7, 8, 32, 47, 56, 57, 63, 64, 79, 95, 106, 124, 125, 156, 159, 160, 161, 162, 168, 176, 183, 184, 191, 219, 220, 224, 236, 243, 255])

found_match = False
for count in range(lower_bound, upper_bound + 1):
    private_key = lfsr_66.generate_private_key()

    private_key_bytes = private_key.to_bytes((private_key.bit_length() + 7) // 8, byteorder='big')
    public_key = hashlib.sha256(private_key_bytes).digest()
    hash160_public_key = hash160(public_key)
    public_address = base58check(b"\x00" + hash160_public_key)

    if beginning_int_66 <= private_key <= end_int_66 and public_address.decode() == desired_public_address and hash160_public_key == desired_hash160:
        found_match = True
        print("Found the matching private key!")
        print("Private Key: ", private_key)
        print("Public Address: ", public_address.decode())
        break

    lfsr_66.shift(1)

    if count % 100000 == 0:
        print(f"Progress (Keyspace 66): {count}/{upper_bound}")

if not found_match:
    print("Matching private key not found within the specified range.")
