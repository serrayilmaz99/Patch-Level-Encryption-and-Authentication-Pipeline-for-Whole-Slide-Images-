PKDF2 : Outputs a long pseudorandom key
password -> PKDF2 (pass, salt)
[:32] enc
[32:] MAC

AAD -> y,x,shape,index,mode

Hmac -> hash-based

tag -> hmac.new(key.mac, aad+c)

nonce = get_random_bytes(8)
cipher = AES.new(self.key_enc, AES.MODE_CTR, nonce=nonce)
ciphertext = cipher.encrypt(patch_bytes)

nonce = get_random_bytes(16)
cipher = AES.new(self.key_enc, AES.MODE_CBC, iv=nonce)
ciphertext = cipher.encrypt(pad(patch_bytes, AES.block_size))

nonce = b""
cipher = AES.new(self.key_enc, AES.MODE_ECB)
ciphertext = cipher.encrypt(pad(patch_bytes, AES.block_size))

Bit-Flip -> ciphertext'
Patch-Swap -> AAD'
tag' -> hmac.new(key.mac, aad+c)

cbc slowest -> CBC is sequential, not parallelize, add/remove/verify/compute padding

block size : fixed-length chunk of data that a block cipher processes
AES : Block size: 128 bits (16 bytes)
AES-256 -> 256-bit (32-byte) key

AES : Symmetric-key block cipher, Standardized, BYTES PERMUTATİON