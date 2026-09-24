# Decode a raw password obtained by b_wincred_get_raw

Defaults to 'auto' encoding, which uses `b_wincred_decode_auto` to
accomplish the decoding (this works with decoding either UTF-8 or
UTF-16LE encodings). In the case where an encoding is specified, use
that to convert the raw password.

## Usage

``` r
b_wincred_decode(password, encoding = "auto")
```

## Arguments

- password:

  A raw byte string returned from `b_wincred_get_raw`.

- encoding:

  A character value, specifying an encoding to use. Defaults to 'auto',
  which will decode either of UTF-8 or UTF-16LE.

## Value

A character value containing a password.
