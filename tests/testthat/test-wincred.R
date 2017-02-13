
context("Windows credential store")

test_that("low level API", {
  skip_if_not_win()

  keyring <- random_keyring()
  service <- random_service()
  username <- random_username()
  password <- random_password()

  target <- backend_wincred_target(keyring, service, username)

  expect_false(backend_wincred_i_exists(target))
  expect_silent(backend_wincred_i_set(target, password, username, session = TRUE))
  expect_true(backend_wincred_i_exists(target))
  expect_equal(backend_wincred_i_get(target), password)
  expect_true(target %in% backend_wincred_i_enumerate("*"))

  expect_silent(backend_wincred_i_delete(target))
  expect_false(backend_wincred_i_exists(target))
  expect_false(target %in% backend_wincred_i_enumerate("*"))
})
