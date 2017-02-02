
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

test_that("set, get, delete without username", {
  skip_if_not_linux()

  service <- random_service()
  password <- random_password()

  backend <- backend_secret_service()

  expect_silent(
    key_set_with_value(service, password = password, backend = backend)
  )

  expect_equal(key_get(service, backend = backend), password)

  expect_silent(key_delete(service, backend = backend))
})

test_that("set can update", {
  skip_if_not_linux()

  service <- random_service()
  username <- random_username()
  password <- random_password()

  backend <- backend_secret_service()

  expect_silent({
    key_set_with_value(service, username, "foobar", backend = backend)
    key_set_with_value(service, username, password, backend = backend)
  })

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
})
