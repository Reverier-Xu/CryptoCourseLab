from Reverier.Utils import bit_count
import base64

def calculate_hamming_distance(bytes_1, bytes_2):
    hamming_distance = 0
    for b1, b2 in zip(bytes_1, bytes_2):
        difference = b1 ^ b2
        hamming_distance += bit_count(difference)
    return hamming_distance


def judge_score(input_bytes):
    character_frequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }
    return sum([character_frequencies.get(chr(byte), 0) for byte in input_bytes.lower()])


def xor_bytes(input_bytes, char_value):
    return bytes([byte ^ char_value for byte in input_bytes])


def bruteforce_xor_bytes(cipher_text):
    potential_messages = []
    class Message:
        def __init__(self, key, message):
            self.key = key
            self.message = message
            self.score = judge_score(message)
    for key_value in range(0xFF + 1):
        message = xor_bytes(cipher_text, key_value)
        score = judge_score(message)
        potential_messages.append(Message(key_value, message))
    return max(potential_messages, key=lambda x: x.score)


def break_repeating_key_xor(ciphertext):
    average_distances = []

    class KeyDistance:
        def __init__(self, key, distance):
            self.key = key
            self.distance = distance

    for keysize in range(2,41):
        distances = []
        chunks = [ciphertext[i : i+keysize] for i in range(0, len(ciphertext), keysize)]
        
        for i in range(0, len(chunks) - 1, 2):
            distances.append(calculate_hamming_distance(chunks[i], chunks[i+1]) / keysize)
        average_distances.append(KeyDistance(keysize, sum(distances) / len(distances)))
    possible_key_lengths = sorted(average_distances, key=lambda x: x.distance)[0]
    possible_plaintext = []
    key = b''
    possible_key_length = possible_key_lengths['key']
    for i in range(possible_key_length):
        block = b''
        for j in range(i, len(ciphertext), possible_key_length):
            block += bytes([ciphertext[j]])
        key += bytes([bruteforce_xor_bytes(block)['key']]) 
    possible_plaintext.append((repeating_key_xor(ciphertext, key), key)) 
    return max(possible_plaintext, key=lambda x: judge_score(x[0]))


def repeating_key_xor(message_bytes, key):
    output_bytes = b''
    index = 0
    for byte in message_bytes:
        output_bytes += bytes([byte ^ key[index]])
        if (index + 1) == len(key):
            index = 0
        else:
            index += 1
    return output_bytes


with open('./week1/6.txt') as input_file:
    ciphertext = base64.b64decode(input_file.read())
result, key = break_repeating_key_xor(ciphertext)
print("Key: {}\nMessage: {}".format(key, result))
