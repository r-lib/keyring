
context("Windows credential store")

test_that("set raw, get raw, delete", {
  skip_if_not_win()
  skip_on_cran()

  service <- random_service()
  username <- random_username()
  password <- random_password()

  expect_silent(wincred_set_with_raw_value(service, username, charToRaw(password)))
  expect_equal(wincred_get_username(service), username)
  expect_equal(wincred_get_raw(service), charToRaw(password))
  expect_equal(wincred_get_raw(service, username), charToRaw(password))
  expect_silent(wincred_delete(service))
})

test_that("set, get, delete", {
  skip_if_not_win()
  skip_on_cran()

  service <- random_service()
  username <- random_username()
  password <- random_password()

  expect_silent(wincred_set_with_value(service, username, password))
  expect_equal(wincred_get_username(service), username)
  expect_equal(wincred_get(service), password)
  expect_equal(wincred_get(service, username), password)
  expect_silent(wincred_delete(service))
})

test_that("set can update password", {
  skip_if_not_win()
  skip_on_cran()

  service <- random_service()
  username <- random_username()
  password <- random_password()

  expect_silent({
    wincred_set_with_value(service, username, "foobar")
    wincred_set_with_value(service, username, password)
  })

  expect_equal(wincred_get(service, username), password)

  expect_silent(wincred_delete(service, username))
})

test_that("list", {
  skip_if_not_win()
  skip_on_cran()

  service <- random_service()
  username <- random_username()
  password <- random_password()

  expect_silent({
    wincred_set_with_value(service, username, password)
    list <- wincred_list()
  })

  expect_equal(list[match(service, list)], service)

  list2 <- wincred_list(service)
  expect_equal(length(list2), 1)
  expect_equal(list2, service)

  expect_silent(wincred_delete(service, username))
})
