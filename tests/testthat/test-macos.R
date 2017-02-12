
context("macOS keyring")

test_that("set, get, delete", {
  skip_if_not_macos()

  service <- random_service()
  username <- random_username()
  password <- random_password()

  backend <- backend_macos()

  expect_silent(
    key_set_with_value(service, username, password, backend = backend)
  )

  expect_equal(key_get(service, username, backend = backend), password)

  expect_silent(key_delete(service, username, backend = backend))
})

test_that("set, get, delete without username", {
  skip_if_not_macos()

  service <- random_service()
  password <- random_password()

  backend <- backend_macos()

  expect_silent(
    key_set_with_value(service, password = password, backend = backend)
  )

  expect_equal(key_get(service, backend = backend), password)

  expect_silent(key_delete(service, backend = backend))
})

test_that("set can update", {
  skip_if_not_macos()

  service <- random_service()
  username <- random_username()
  password <- random_password()

  backend <- backend_macos()

  expect_silent({
    key_set_with_value(service, username, "foobar", backend = backend)
    key_set_with_value(service, username, password, backend = backend)
  })

  expect_equal(key_get(service, username, backend = backend), password)

  expect_silent(key_delete(service, username, backend = backend))
})

test_that("list", {
  skip_if_not_macos()

  service <- random_service()
  username <- random_username()
  password <- random_password()

  backend <- backend_macos()

  expect_silent({
    key_set_with_value(service, username, password, backend = backend)
    list <- key_list(backend = backend)
  })

  expect_equal(list$username[match(service, list$service)], username)

  list2 <- key_list(service = service, backend = backend)
  expect_equal(nrow(list2), 1)
  expect_equal(list2$username, username)

  expect_silent(key_delete(service, username, backend = backend))
})

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
  backend$create_keyring <- function(backend, pw) {
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
