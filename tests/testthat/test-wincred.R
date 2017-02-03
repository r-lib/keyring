
context("Windows credential store")

test_that("set, get, delete", {
  skip_if_not_win()

  service <- random_service()
  username <- random_username()
  password <- random_password()

  backend <- backend_wincred()

  expect_silent(
    key_set_with_value(service, username, password, backend = backend)
  )

  expect_equal(key_get(service, username, backend = backend), password)

  expect_silent(key_delete(service, username, backend = backend))
})
