
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

test_that("lock/unlock keyrings", {
  skip("requires interaction")
  skip_if_not_linux()

  keyring <- random_keyring()
  backend <- backend_secret_service(keyring = keyring)

  ## This asks for a password interactively.
  ## keyring_create(backend = backend)
  backend_secret_service_create_keyring_direct(backend$keyring,
                                               password = "secret123!")

  ## It is unlocked by default
  list <- keyring_list(backend = backend)
  expect_true(keyring %in% list$keyring)
  expect_false(list$locked[match(keyring, list$keyring)])

  ## Lock it
  keyring_lock(backend = backend)
  list <- keyring_list(backend = backend)
  expect_true(list$locked[match(keyring, list$keyring)])

  ## Unlock it
  keyring_unlock(backend = backend, password = "secret123!")
  list <- keyring_list(backend = backend)
  expect_false(list$locked[match(keyring, list$keyring)])

  expect_silent(keyring_delete(backend = backend))
})
