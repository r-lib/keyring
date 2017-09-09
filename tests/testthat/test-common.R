
context("Common API")

opts <- options(keyring_warn_for_env_fallback = FALSE)
on.exit(options(opts), add = TRUE)

test_that("set, get, delete", {

  skip_on_cran()
  
  service <- random_service()
  username <- random_username()
  password <- random_password()

  expect_silent(key_set_with_value(service, username, password))
  expect_equal(key_get(service, username), password)
  expect_silent(key_delete(service, username))
})

test_that("set, get, delete without username", {

  skip_on_cran()
  
  service <- random_service()
  password <- random_password()

  expect_silent(key_set_with_value(service, password = password))
  expect_equal(key_get(service), password)

  expect_silent(key_delete(service))
})

test_that("set can update", {

  skip_on_cran()
  
  service <- random_service()
  username <- random_username()
  password <- random_password()

  expect_silent({
    key_set_with_value(service, username, "foobar")
    key_set_with_value(service, username, password)
  })

  expect_equal(key_get(service, username), password)

  expect_silent(key_delete(service, username))
})

test_that("list", {

  skip_on_cran()
  
  if (default_backend()$name == "env") skip("'env' backend has no 'list' support")

  service <- random_service()
  username <- random_username()
  password <- random_password()

  expect_silent({
    key_set_with_value(service, username, password)
    list <- key_list()
  })

  expect_equal(list$username[match(service, list$service)], username)

  list2 <- key_list(service = service)
  expect_equal(nrow(list2), 1)
  expect_equal(list2$username, username)

  expect_silent(key_delete(service, username))
})
