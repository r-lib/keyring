# base64

    Code
      base64_decode("oi7mFx/aLCc3qZ7vQMQQdwwiGq32gB3ylYm6urM9aGY=")
    Output
       [1] a2 2e e6 17 1f da 2c 27 37 a9 9e ef 40 c4 10 77 0c 22 1a ad f6 80 1d f2 95
      [26] 89 ba ba b3 3d 68 66

# aes_cbc_encrypt, aes_cbc_decrypt

    Code
      aes_cbc_decrypt(y, key2)
    Condition
      Error in `aes_cbc_decrypt()`:
      ! Cannot decrypt AES CBC, probably wrong key?

---

    Code
      aes_cbc_encrypt(x, raw(5), iv = iv)
    Condition
      Error in `aes_cbc_encrypt()`:
      ! Invalid 'key', must have 32 bytes
    Code
      aes_cbc_encrypt(x, key, iv = raw(10))
    Condition
      Error in `aes_cbc_encrypt()`:
      ! Invalid 'iv', must have 16 bytes
    Code
      aes_cbc_decrypt(raw(17), key, iv)
    Condition
      Error in `aes_cbc_decrypt()`:
      ! Invalid message length, must be multiple of 16

