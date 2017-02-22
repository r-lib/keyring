
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
  assert_that(is_non_empty_string(service))
  assert_that(is_string_or_null(username))
  assert_that(is_keyring_backend(backend))

  backend$get(backend, service, username)
}

#' @export
#' @rdname key_get

key_set <- function(service, username = NULL, backend = default_backend()) {
  assert_that(is_non_empty_string(service))
  assert_that(is_string_or_null(username))
  assert_that(is_keyring_backend(backend))

  backend$set(backend, service, username)
}

#' @export
#' @rdname key_get

key_set_with_value <- function(service, username = NULL, password = NULL,
                               backend = default_backend()) {
  assert_that(is_non_empty_string(service))
  assert_that(is_keyring_backend(backend))
  assert_that(is_string(password))

  backend$set_with_value(backend, service, username, password)
}

#' @export
#' @rdname key_get

key_delete <- function(service, username = NULL,
                       backend = default_backend()) {
  assert_that(is_non_empty_string(service))
  assert_that(is_string_or_null(username))
  assert_that(is_keyring_backend(backend))

  backend$delete(backend, service, username)
}

#' @export
#' @rdname key_get

key_list <- function(service = NULL, backend = default_backend()) {
  assert_that(is_non_empty_string_or_null(service))
  assert_that(is_keyring_backend(backend))

  check_supported(backend, "list")

  backend$list(backend, service)
}

#' Manage keyrings
#'
#' Most keyring backends support multiple keyrings. A keyring is a
#' collection of keys that can be treated as a unit. A keyring typically
#' has a name and a password to unlock it. Once a keyring is unlocked,
#' it remains unlocked until the end of the user session, or until it is
#' explicitly locked again.
#'
#' Backends typically have a default keyring, which is unlocked
#' automatically when the user logs in. This keyring does not need to be
#' unlocked explicitly.
#'
#' You can configure the keyring to use via R options or environment
#' variables (see [default_backend()]), or you can also specify it
#' directly in the backend calls or in the call to [default_backend().
#'
#' `keyring_support` checks if a backend supports multiple keyrings.
#'
#' `keyring_create` creates a new keyring. It asks for a password if no
#' password is specified.
#'
#' `keyring_list` lists all existing keyrings.
#'
#' `keyring_delete` deletes a keyring. Deleting a non-empty keyring
#' requires confirmation, and the default keyring can only be deleted if
#' specified explicitly. On some backends (e.g. Windows Credential Store),
#' the default keyring cannot be deleted at all.
#'
#' `keyring_lock` locks a keyring. On some backends (e.g. Windows
#' Credential Store), the default keyring cannot be locked.
#'
#' `keyring_unlock` unlocks a keyring. If a password is not specified,
#' it will be read in interactively.
#'
#' @param backend The backend to use. You will also need to specify the
#'   keyring to this backend, if a non-default keyring is desired.
#'   See examples below.
#' @param password The password to unlock the keyring. If not specified
#'   or `NULL`, it will be read from the console.
#'
#' @export
#' @examples
#' default_backend()
#' keyring_support()
#' keyring_support(backend = backend_env())
#'
#' ## This might ask for a password, so we do not run it by default
#' \dontrun{
#' keyring_create(default_backend(keyring = "foobar"))
#' key_set_with_value("R-test-service", "donaldduck", password = "secret",
#'                    backend = default_backend(keyring = "foobar"))
#' key_get("R-test-service", "donaldduck",
#'         backend = default_backend(keyring = "foobar"))
#' key_list(backend = default_backend(keyring = "foobar"))
#' key_delete(backend = default_backend(keyring = "foobar"))
#' }

keyring_support <- function(backend = default_backend()) {
  assert_that(is_keyring_backend(backend))

  "keyring" %in% names(backend)
}

#' @export
#' @rdname keyring_support

keyring_create <- function(backend = default_backend()) {
  assert_that(is_keyring_backend(backend))

  check_supported(backend, "create_keyring")

  backend$create_keyring(backend)
}

#' @export
#' @rdname keyring_support

keyring_list <- function(backend = default_backend()) {
  assert_that(is_keyring_backend(backend))

  check_supported(backend, "list_keyring")

  backend$list_keyring(backend)
}

#' @export
#' @rdname keyring_support

keyring_delete <- function(backend = default_backend()) {
  assert_that(is_keyring_backend(backend))

  check_supported(backend, "delete_keyring")

   backend$delete_keyring(backend)
}

#' @export
#' @rdname keyring_support

keyring_lock <- function(backend = default_backend()) {
  assert_that(is_keyring_backend(backend))

  check_supported(backend, "lock_keyring")

  backend$lock_keyring(backend)
}

#' @export
#' @rdname keyring_support

keyring_unlock <- function(backend = default_backend(), password = NULL) {
  assert_that(is_keyring_backend(backend))

  check_supported(backend, "unlock_keyring")

  backend$unlock_keyring(backend, password)
}
