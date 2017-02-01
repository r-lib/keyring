
context("Secret Service API")

test_that("set, get, delete", {
  skip_if_not_linux()

  service <- random_service()
  username <- random_username()
  password <- random_password()

  backend <- backend_secret_service()

  expect_silent(
    key_set_with_value(service, username, password, backend = backend)
  )

  expect_equal(key_get(service, username, backend = backend), password)

  expect_silent(key_delete(service, username, backend = backend))

})

test_that("list", {
  skip_if_not_linux()

  service <- random_service()
  username <- random_username()
  password <- random_password()

  backend <- backend_secret_service()

  expect_silent({
    key_set_with_value(service, username, password, backend = backend)
    list <- key_list(backend = backend)
  })

  expect_equal(list$username[match(service, list$service)], username)

  list2 <- key_list(service = service, backend = backend)
  expect_equal(list2$service, service)
  expect_equal(list2$username, username)

  expect_silent(key_delete(service, username, backend = backend))
})
