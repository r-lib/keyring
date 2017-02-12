
context("Secret Service API")

test_that("specify keyring explicitly", {
  skip_if_not_linux()

  service <- random_service()
  username <- random_username()
  password <- random_password()

  backend <- backend_secret_service("Login")

  expect_silent(
    key_set_with_value(service, username, password, backend = backend)
  )

  expect_equal(key_get(service, username, backend = backend), password)

  expect_silent(key_delete(service, username, backend = backend))
})

test_that("creating keychains", {
  skip("requires interaction")
  skip_if_not_linux()

  keyring <- random_keyring()
  backend <- backend_secret_service(keyring = keyring)

  keyring_create(backend = backend)

  keyring_list(backend = backend)

  service <- random_service()
  username <- random_username()
  password <- random_password()

  expect_silent(
    key_set_with_value(service, username, password, backend = backend)
  )

  expect_equal(key_get(service, username, backend = backend), password)

  expect_silent(key_delete(service, username, backend = backend))

  expect_silent(keyring_delete(backend = backend))

  expect_false(keyring %in% keyring_list(backend = backend)$keyring)
})
