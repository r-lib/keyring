
context("Secret Service API")

opts <- options(keyring_warn_for_env_fallback = FALSE)
on.exit(options(opts), add = TRUE)

test_that("specify keyring explicitly", {
  skip_if_not_secret_service()
  skip_on_cran()

  service <- random_service()
  username <- random_username()
  password <- random_password()

  kb <- backend_secret_service$new("Login")

  expect_silent(
    kb$set_with_value(service, username, password)
  )

  expect_equal(kb$get(service, username), password)

  expect_silent(kb$delete(service, username))
})

test_that("creating keychains", {
  skip("requires interaction")
  skip_if_not_secret_service()
  skip_on_cran()

  keyring <- random_keyring()
  kb <- backend_secret_service$new(keyring = keyring)

  kb$keyring_create(keyring = keyring)

  kb$keyring_list()

  service <- random_service()
  username <- random_username()
  password <- random_password()

  expect_silent(
    kb$set_with_value(service, username, password)
  )

  expect_equal(kb$get(service, username), password)

  expect_silent(kb$delete(service, username))

  expect_silent(kb$keyring_delete(keyring = keyring))

  expect_false(keyring %in% keyring_list()$keyring)
})

test_that("lock/unlock keyrings", {
  skip("requires interaction")
  skip_if_not_secret_service()
  skip_on_cran()

  keyring <- random_keyring()
  kb <- backend_secret_service$new(keyring = keyring)
  # interactive
  kb$.__enclos_env__$private$keyring_create_direct(keyring)

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

  ## Unlock it (interactive)
  kb$keyring_unlock()
  expect_false(kb$keyring_is_locked())
  list <- keyring_list()
  expect_false(list$locked[match(keyring, list$keyring)])

  expect_silent(kb$keyring_delete(keyring = keyring))
})
