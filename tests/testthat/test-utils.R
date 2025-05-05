
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
