
context("env keyring")

test_that("set, get, delete", {

  service <- random_service()
  username <- random_username()
  password <- random_password()

  kb <- backend_env$new()
  var <- kb$.__enclos_env__$private$env_to_var(service, username)

  expect_silent(
    kb$set_with_value(service, username, password)
  )
  
  expect_equal(kb$list(service)$username, c(username))

  expect_equal(kb$get(service, username), password)
  expect_equal(Sys.getenv(var, "foo"), password)

  expect_silent(kb$delete(service, username))
  expect_equal(Sys.getenv(var, "foo"), "foo")
})

test_that("set, get, delete, without username", {
  service <- random_service()
  password <- random_password()

  kb <- backend_env$new()
  var <- kb$.__enclos_env__$private$env_to_var(service, NULL)

  expect_silent(
    kb$set_with_value(service, password = password)
  )

  expect_equal(kb$get(service), password)
  expect_equal(Sys.getenv(var, "foo"), password)

  expect_silent(kb$delete(service))
  expect_equal(Sys.getenv(var, "foo"), "foo")
})

