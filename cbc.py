#changed 3/19/2018
#now this is a changed program
ASCII_BITS = 8
from Crypto.Cipher import AES

def test():
    key = string_to_bits('ANITA')
    #print key
    #print 1
    iv = string_to_bits('SAKSHIANNNDANITA')
    #print "\n\n\n", iv
    plaintext = string_to_bits('My name is Radhika Jain')
    #print "\n\n\n", plaintext

    cipher = cipher_block_chaining(plaintext, key, iv, 128, aes_encoder)
    print cipher



def string_to_bits(s):
    retval = []
   
    for group in map(chr_to_bit,s):
        
        retval = retval + group
        
    return retval



def chr_to_bit(c):
    return pad_bits(convert_to_bits(ord(c)), ASCII_BITS)

def convert_to_bits(n):
    retval = []
    if n == 0:
        return [0]
    while n > 0:
        retval = [(n % 2)]+ retval
        n = n / 2

    return retval

def pad_bits(bits_array, pad):
    assert len(bits_array) <= pad
    return [0] * (pad - len(bits_array)) + bits_array

def cipher_block_chaining(plaintext, key, init_vec, block_size, block_enc):

    #plaintext = bits to be encoded or encrypted
    #key = bits used as key for a block of message bits
    #init_vec = bits used as initialization vector for the block encoder or block encryption
    #block_size = size of message block, for AES, we use 128 bit block
    #block_enc = function that encodes a block using key

    cipher = []
    xor_input = init_vector

    #break plain text into blocks
    #encode each one

    for i in range(len(plaintext) / block_size + 1):
        start = i * block_size
        if (start >= len(plaintext)):
            break
        end = min((i + 1) * block_size, len(plaintext))

        #getting each block
        block = plaintext[start:end]

        #xoring the 128 bit block with 128 bit init_vector
        msg_xor_iv = xor(block, xor_input)

        output = block_enc(msg_xor_iv, key)
        xor_input = output
        cipher.extend(output)
        
    return cipher

def xor(x, y):
    retval = []
    for xx,yy in zip(x,y):
        retval = retval + [xx ^ yy]
    return retval

def aes_encoder(block, key):
    block = pad_bits_append(block, len(key))
    block = bit_to_string(block)
    key = bit_to_string(key)
    ecb = AES.new(key, AES.MODE_ECB)
    return string_to_bits(ecb.encrypt(block))

def pads_bit_append(block, size):
    diff = max(0, size - len(block))
    return block + [0] * diff


def bits_to_string(b):
    return ''.join( [ bits_to_char( b[i:i+ASCII_BITS] ) for i in range(0, len(b), ASCII_BITS ) ] )

def bits_to_char(b):
    assert len(b) == ASCII_BITS
    value = 0
    for e in b:
        value = (value * 2) + e
    return chr(value)

test()
