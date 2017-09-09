
context("macOS keyring")

test_that("specify keyring explicitly", {
  skip_if_not_macos()
  skip_on_cran()

  service <- random_service()
  username <- random_username()
  password <- random_password()

  kb <- backend_macos$new(keyring = "login")

  expect_silent(
    kb$set_with_value(service, username, password)
  )

  expect_equal(kb$get(service, username), password)

  expect_silent(kb$delete(service, username))
})

test_that("creating keychains", {
  skip_if_not_macos()
  skip_on_cran()

  keyring <- random_keyring()
  kb <- backend_macos$new()
  
  ## To avoid an interactive password
  kb$.__enclos_env__$private$keyring_create_direct(keyring, "secret123!")

  list <- kb$list(keyring = keyring)
  expect_equal(nrow(list), 0)

  service <- random_service()
  username <- random_username()
  password <- random_password()

  expect_silent(
    kb$set_with_value(service, username, password)
  )

  expect_equal(kb$get(service, username), password)

  expect_silent(kb$delete(service, username))

  expect_silent(kb$keyring_delete(keyring = keyring))

  expect_false(keyring %in% kb$keyring_list()$keyring)
})

test_that("creating keychains 2", {
  skip_if_not_macos()
  skip_on_cran()

  keyring <- random_keyring()
  kb <- backend_macos$new()

  ## To avoid an interactive password
  kb$.__enclos_env__$private$keyring_create_direct(keyring, "secret")
  kb$keyring_set_default(keyring)

  service <- random_service()
  username <- random_username()
  password <- random_password()

  expect_silent(
    kb$set_with_value(service, username, password)
  )

  expect_equal(kb$get(service, username), password)
  expect_silent(kb$delete(service, username))
  expect_silent(kb$keyring_delete(keyring = keyring))
  expect_false(keyring %in% kb$keyring_list()$keyring)
})

test_that("keyring file at special location", {

  skip_if_not_macos()
  skip_on_cran()

  keyring <- tempfile(fileext = ".keychain")
  kb <- backend_macos$new(keyring = keyring)

  kb$.__enclos_env__$private$keyring_create_direct(keyring, "secret123!")

  service <- random_service()
  username <- random_username()
  password <- random_password()

  expect_silent(
    kb$set_with_value(service, username, password)
  )
  expect_equal(kb$get(service, username), password)
  expect_silent(kb$delete(service, username))
  expect_silent(kb$keyring_delete(keyring = keyring))
  expect_false(keyring %in% kb$keyring_list()$keyring)
  expect_false(file.exists(keyring))
})

test_that("errors", {

  skip_if_not_macos()
  skip_on_cran()

  ## Non-existing keychain
  expect_error(
    backend_macos$new(tempfile())$list(),
    "cannot open keychain"
  )

  ## Getting non-existing password
  expect_error(
    backend_macos$new()$get(random_service(), random_username()),
    "cannot get password"
  )

  ## Deleting non-existing password
  expect_error(
    backend_macos$new()$delete(random_service(), random_username()),
    "cannot delete password"
  )

  ## Create keychain without access to file
  kb <- backend_macos$new()
  expect_error(
    kb$.__enclos_env__$private$keyring_create_direct("/xxx", "secret123!"),
    "cannot create keychain"
  )
})

test_that("lock/unlock keyrings", {
  skip_if_not_macos()
  skip_on_cran()

  keyring <- random_keyring()
  kb <- backend_macos$new(keyring = keyring)
  kb$.__enclos_env__$private$keyring_create_direct(keyring, "secret123!")

  ## It is unlocked by default
  expect_false(kb$keyring_is_locked())
  list <- kb$keyring_list()
  expect_true(keyring %in% list$keyring)
  expect_false(list$locked[match(keyring, list$keyring)])

  ## Lock it
  kb$keyring_lock()
  expect_true(kb$keyring_is_locked())
  list <- kb$keyring_list()
  expect_true(list$locked[match(keyring, list$keyring)])

  ## Unlock it
  kb$keyring_unlock(password = "secret123!")
  expect_false(kb$keyring_is_locked())
  list <- kb$keyring_list()
  expect_false(list$locked[match(keyring, list$keyring)])

  expect_silent(kb$keyring_delete(keyring = keyring))
})
