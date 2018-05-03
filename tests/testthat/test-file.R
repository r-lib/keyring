
context("file-based keyring")

test_that("specify keyring explicitly", {

  service <- random_service()
  username <- random_username()
  password <- random_password()
  keyring <- random_keyring()

  kb <- backend_file$new(keyring = keyring)

  expect_silent(
    kb$set_with_value(service, username, password)
  )

  expect_equal(kb$get(service, username), password)
})
