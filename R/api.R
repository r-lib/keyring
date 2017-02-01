
#' Query, set, delete list keys in a keyring
#'
#' @param service Service name, a character scalar.
#' @param username Username, a character scalar, or `NULL` if the key
#'   is not associated with a username.
#' @param password The secret to store. For `key_set`, it is read from
#'   the console, interactively. `key_set_with_value` can be also used
#'   in non-interactive mode.
#' @param backend Backend to use. See [backends].
#' @return `key_get` returns a character scalar, the password or other
#'   confidential information that was stored in the key.
#'   `key_list` returns a list of keys, i.e. service names and usernames,
#'   in a data frame.
#'
#' @export
#' @examples
#' # TODO

key_get <- function(service, username = NULL, backend = default_backend()) {
  assert_that(is_string(service))
  assert_that(is_string_or_null(username))
  assert_that(is_keyring_backend(backend))

  backend$get(backend, service, username)
}

#' @export
#' @rdname key_get

key_set <- function(service, username = NULL, backend = default_backend()) {
  assert_that(is_string(service))
  assert_that(is_string_or_null(username))
  assert_that(is_keyring_backend(backend))

  backend$set(backend, service, username)
}

#' @export
#' @rdname key_get

key_set_with_value <- function(service, username = NULL, password = NULL,
                               backend = default_backend()) {
  assert_that(is_string(service))
  assert_that(is_keyring_backend(backend))
  assert_that(is_string(password))

  backend$set_with_value(backend, service, username, password)
}

#' @export
#' @rdname key_get

key_delete <- function(service, username = NULL,
                       backend = default_backend()) {
  assert_that(is_string(service))
  assert_that(is_string_or_null(username))
  assert_that(is_keyring_backend(backend))

  backend$delete(backend, service, username)
}

#' @export
#' @rdname key_get

key_list <- function(service = NULL, backend = default_backend()) {
  assert_that(is_string_or_null(service))
  assert_that(is_keyring_backend(backend))

  check_supported(backend, "list")

  backend$list(backend, service)
}

#' @export

keyring_create <- function(backend = default_backend()) {
  assert_that(is_keyring_backend(backend))

  check_supported(backend, "create_keyring")

  backend$create_keyring(backend)
}

#' @export

keyring_list <- function(backend = default_backend()) {
  assert_that(is_keyring_backend(backend))

  check_supported(backend, "list_keyring")

  backend$list_keyring(backend)
}

#' @export

keyring_delete <- function(backend = default_backend()) {
  assert_that(is_keyring_backend(backend))

  check_supported(backend, "delete_keyring")

  backend$delete_keyring(backend)
}
