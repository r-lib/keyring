
context("macOS keyring")

test_that("specify keyring explicitly", {
  skip_if_not_macos()

  service <- random_service()
  username <- random_username()
  password <- random_password()

  backend <- backend_macos("login")

  expect_silent(
    key_set_with_value(service, username, password, backend = backend)
  )

  expect_equal(key_get(service, username, backend = backend), password)

  expect_silent(key_delete(service, username, backend = backend))
})

test_that("creating keychains", {
  skip_if_not_macos()

  keyring <- random_keyring()
  backend <- backend_macos(keyring = keyring)

  ## This asks for a password interactively.
  ## keyring_create(backend = backend)
  backend_macos_create_keyring_direct(backend$keyring, pw = "secret123!")

  list <- key_list(backend = backend)
  expect_equal(nrow(list), 0)

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

test_that("creating keychains, interactive", {
  skip_if_not_macos()

  keyring <- random_keyring()
  backend <- backend_macos(keyring = keyring)
  backend$keyring_create <- function(backend, pw) {
    backend_macos_create_keyring_direct(backend$keyring, "secret")
  }

  keyring_create(backend = backend)

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

test_that("keyring file at special location", {

  skip_if_not_macos()

  keyring <- tempfile(fileext = ".keychain")
  backend <- backend_macos(keyring = keyring)

  backend_macos_create_keyring_direct(backend$keyring, pw = "secret123!")

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
  expect_false(file.exists(keyring))
})

test_that("errors", {

  skip_if_not_macos()

  ## Non-existing keychain
  expect_error(
    key_list(backend = backend_macos(tempfile())),
    "cannot open keychain"
  )

  ## Getting non-existing password
  expect_error(
    key_get(random_service(), random_username(), backend = backend_macos()),
    "cannot get password"
  )

  ## Deleting non-existing password
  expect_error(
    key_delete(random_service(), random_username(),
               backend = backend_macos()),
    "cannot delete password"
  )

  ## Create keychain without access to file
  expect_error(
    backend_macos_create_keyring_direct("/xxx", pw = "secret123!"),
    "cannot create keychain"
  )
})

test_that("lock/unlock keyrings", {
  skip_if_not_macos()

  keyring <- random_keyring()
  backend <- backend_macos(keyring = keyring)

  ## This asks for a password interactively.
  ## keyring_create(backend = backend)
  backend_macos_create_keyring_direct(backend$keyring, pw = "secret123!")

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
