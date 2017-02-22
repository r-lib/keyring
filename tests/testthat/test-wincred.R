
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

test_that("creating keychains", {
  skip_if_not_win()

  keyring <- random_keyring()
  backend <- backend_wincred(keyring = keyring)

  ## This asks for a password interactively.
  ## keyring_create(backend = backend)
  backend_wincred_create_keyring_direct(backend$keyring, pw = "secret123!")
  expect_true(keyring %in% keyring_list(backend = backend)$keyring)


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
  skip_if_not_win()

  keyring <- random_keyring()
  backend <- backend_wincred(keyring = keyring)
  backend$create_keyring <- function(backend, pw) {
    backend_wincred_create_keyring_direct(backend$keyring, "secret")
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

test_that("lock/unlock keyrings", {
  skip_if_not_win()

  keyring <- random_keyring()
  backend <- backend_wincred(keyring = keyring)

  ## This asks for a password interactively.
  ## keyring_create(backend = backend)
  backend_wincred_create_keyring_direct(backend$keyring, pw = "secret123!")

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

test_that(": in keyring, service and usernames", {
  skip_if_not_win()

  keyring <- paste0("foo:", random_keyring())
  service <- paste0("bar:", random_service())
  username <- paste0("foobar:", random_username())
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
