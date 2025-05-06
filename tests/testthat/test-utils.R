test_that("base64", {
  expect_equal(base64_encode(charToRaw("foobar")), "Zm9vYmFy")
  expect_equal(base64_encode(charToRaw(" ")), "IA==")
  expect_equal(base64_encode(charToRaw("")), "")

  x <- charToRaw(paste(sample(letters, 10000, replace = TRUE), collapse = ""))
  expect_equal(base64_decode(base64_encode(x)), x)

  for (i in 5:32) {
    mtcars2 <- unserialize(base64_decode(base64_encode(
      serialize(mtcars[1:i, ], NULL)
    )))
    expect_identical(mtcars[1:i, ], mtcars2)
  }

  expect_snapshot(
    base64_decode("oi7mFx/aLCc3qZ7vQMQQdwwiGq32gB3ylYm6urM9aGY=")
  )
})

test_that("sha256", {
  x <- charToRaw(basename(tempfile()))
  expect_equal(sha256(x), unclass(openssl::sha256(x)))

  key <- sha256(x)
  txt <- charToRaw("foobar")
  expect_equal(sha256(txt, key), unclass(openssl::sha256(txt, key)))
})

test_that("aes_cbc_encrypt, aes_cbc_decrypt", {
  x <- charToRaw("foobar")
  key <- sha256(charToRaw("secret"))
  y <- aes_cbc_encrypt(x, key)
  iv <- attr(y, "iv")

  expect_equal(y, openssl::aes_cbc_encrypt(x, key, iv = iv))
  expect_equal(aes_cbc_decrypt(y, key), x)

  # wrong key
  # fix iv, so we don't accidentally get a bad key that actually "works"
  iv <- as.raw(c(
    0xe2,
    0x2d,
    0x43,
    0x22,
    0x86,
    0x3f,
    0x02,
    0x11,
    0x90,
    0x98,
    0xd8,
    0x97,
    0x1a,
    0xb2,
    0x7b,
    0x74
  ))
  y <- aes_cbc_encrypt(x, key, iv = iv)
  key2 <- sha256(charToRaw("bad"))
  expect_snapshot(error = TRUE, aes_cbc_decrypt(y, key2))

  # other errors
  expect_snapshot(error = TRUE, {
    aes_cbc_encrypt(x, raw(5), iv = iv)
    aes_cbc_encrypt(x, key, iv = raw(10))
    aes_cbc_decrypt(raw(17), key, iv)
  })
})
