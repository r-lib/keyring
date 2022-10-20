#
#  the SecretsManager API is described as eventually consistent and
#  immediately listing a just-created secret is not guaranteed to work,
#  re-creating one that has just been deleted may not work either.
#  In the list case we cannot tell the difference betwen not found and not
#  propagated.  This should not be an issue in the real world where
#  hopefully the delays between creating and referencing a secret are
#  more than the five minutes that Amazon recommends waiting becore giving up.
#
#  All this means that these tests can appear somewhat flakey when delays
#  appear and disappear.  The list test can both work and not work in the
#  same run and so have had loops added to protect them from failing.
#

context("AWS Secrets Manager")

Sys.setenv(R_KEYRING_TEST_USE_AWS=1)

test_that("set, list, get, delete", {

  skip_on_cran()
  # AWS secret creation costs money, don't do it by accident
  if(Sys.getenv("R_KEYRING_TEST_USE_AWS")[[1]] == "") {
    skip("AWS backend not tested, environment variable R_KEYRING_TEST_USE_AWS not set")
  }
  callerID = try(paws::sts()$get_caller_identity())
  if (inherits(callerID, "try-error")) {
    skip("No AWS credentials to use for testing")
  }

  service <- random_service()
  service2 <- random_service()
  username <- random_username()
  password <- random_password()

  kb <- backend_awssecretsmanager$new()

  expect_true(kb$is_available())

  expect_error(kb$set_with_value(service, username, password))
  expect_silent(kb$set_with_value(service, password = password))
  expect_silent(kb$set_with_value(service2, password = password))
  sleepTime = 1
  sleepCount = 0
  repeat {
    serviceName = kb$list(service)$service
    if (!is.null(serviceName)) {
      break
    }
    sleepCount = sleepCount + 1
    if (sleepCount > 6)
    {
      fail(message = "gave up waiting for AWS secret create to propagate while testing listing a named secret")
    }
    Sys.sleep(sleepTime)
    sleepTime = sleepTime * 2
  }

  expect_equal(serviceName, c(service))

  repeat {
    serviceName = kb$list()$service
    if (length(serviceName) >= 2) {
      break
    }
    sleepCount = sleepCount + 1
    if (sleepCount > 6)
    {
      fail(message = "gave up waiting for AWS secret create to propagate while testing listing multiple secrets")
    }
    Sys.sleep(sleepTime)
    sleepTime = sleepTime * 2
  }

  expect_gte(length(serviceName),2)

  expect_error(kb$get(service, username))

  expect_error(kb$list(service, username))

  expect_error(kb$delete(service, username))

  expect_silent(kb$delete(service))
  expect_silent(kb$delete(service2))
})

test_that("set, get, delete, without username", {

  skip_on_cran()
  # AWS secret creation costs money, don't do it by accident
  if(Sys.getenv("R_KEYRING_TEST_USE_AWS")[[1]] == "") {
    skip("AWS backend not tested, environment variable R_KEYRING_TEST_USE_AWS not set")
  }
  callerID = try(paws::sts()$get_caller_identity())
  if (inherits(callerID, "try-error")) {
    skip("No AWS credentials to use for testing")
  }

  service <- random_service()
  password <- random_password()

  kb <- backend_awssecretsmanager$new()

  expect_silent(kb$set_with_value(service, password = password))

  expect_equal(kb$get(service), password)

  #expect_snapshot(kb$list(),"list")

#  expect_silent(kb$delete(service))
})
