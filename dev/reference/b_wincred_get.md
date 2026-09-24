# Get a key from a Wincred keyring

Get a key from a Wincred keyring

## Usage

``` r
b_wincred_get(self, private, service, username, keyring)
```

## Arguments

- service:

  Service name. Must not be empty.

- username:

  Username. Might be empty.

  1.  We check if the key is on the default keyring.

  2.  If yes, we just return it.

  3.  Otherwise check if the keyring is locked.

  4.  If locked, then unlock it.

  5.  Get the AES key from the keyring.

  6.  Decrypt the key with the AES key.

  Additionally, users may specify an encoding to use when converting the
  password from a byte-string, for compatibility with other software
  such as python's keyring package. This is done via an option, or an
  environment variable.
