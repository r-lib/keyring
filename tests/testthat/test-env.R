
context("env keyring")

test_that("set, get, delete", {

  service <- random_service()
  username <- random_username()
  password <- random_password()

  backend <- backend_env()
  var <- backend_env_to_var(service, username)

  expect_silent(
    key_set_with_value(service, username, password, backend = backend)
  )

  expect_equal(key_get(service, username, backend = backend), password)
  expect_equal(Sys.getenv(var, "foo"), password)

  expect_silent(key_delete(service, username, backend = backend))
  expect_equal(Sys.getenv(var, "foo"), "foo")
})

test_that("set, get, delete, without username", {
  service <- random_service()
  password <- random_password()

  backend <- backend_env()
  var <- backend_env_to_var(service, NULL)

  expect_silent(
    key_set_with_value(service, password = password, backend = backend)
  )

  expect_equal(key_get(service, backend = backend), password)
  expect_equal(Sys.getenv(var, "foo"), password)

  expect_silent(key_delete(service, backend = backend))
  expect_equal(Sys.getenv(var, "foo"), "foo")
})

test_that("no list method", {
  expect_error(
    key_list(backend = backend_env()),
    "Backend .*env.* does not support .*list.*"
  )
})
