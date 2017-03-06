
#' Query, set, delete list keys in a keyring
#'
#' These functions manipulate keys in a keyring. You can think of a keyring
#' as a secure key-value store.
#'
#' `key_get` queries a key from the keyring.
#'
#' `key_set` sets a key in the keyring. The contents of the key is read
#' interactively from the terminal.
#'
#' `key_set_with_value` is the non-interactive pair of `key_set`, to set
#' a key in the keyring.
#'
#' `key_delete` deletes a key.
#'
#' `key_list` lists all keys of a keyring, or the keys for a certain
#' service (if `service` is not `NULL`).
#'
#' @param service Service name, a character scalar.
#' @param username Username, a character scalar, or `NULL` if the key
#'   is not associated with a username.
#' @param password The secret to store. For `key_set`, it is read from
#'   the console, interactively. `key_set_with_value` can be also used
#'   in non-interactive mode.
#' @return `key_get` returns a character scalar, the password or other
#'   confidential information that was stored in the key.
#'
#'   `key_list` returns a list of keys, i.e. service names and usernames,
#'   in a data frame.
#'
#' @export
#' @examples
#' # These examples use the default keyring, and they are interactive,
#' # so, we don't run them by default
#' \dontrun{
#' key_set("R-keyring-test-service", "donaldduck")
#' key_get("R-keyring-test-service", "donaldduck")
#' if (has_keyring_support()) key_list(service = "R-keyring-test-service")
#' key_delete("R-keyring-test-service", "donaldduck")
#' }
#'
#' ## This is non-interactive, assuming that that default keyring
#' ## is unlocked
#' key_set_with_value("R-keyring-test-service", "donaldduck",
#'                    password = "secret")
#' key_get("R-keyring-test-service", "donaldduck")
#' if (has_keyring_support()) key_list(service = "R-keyring-test-service")
#' key_delete("R-keyring-test-service", "donaldduck")

key_get <- function(service, username = NULL, keyring = NULL) {
  assert_that(is_non_empty_string(service))
  assert_that(is_string_or_null(username))
  default_backend()$get(service, username, keyring = keyring)
}

#' @export
#' @rdname key_get

key_set <- function(service, username = NULL, keyring = NULL) {
  assert_that(is_non_empty_string(service))
  assert_that(is_string_or_null(username))
  default_backend()$set(service, username, keyring = keyring)
}

#' @export
#' @rdname key_get

key_set_with_value <- function(service, username = NULL, password = NULL,
                               keyring = NULL) {
  assert_that(is_non_empty_string(service))
  assert_that(is_string(password))
  default_backend()$set_with_value(service, username, password,
                                         keyring = keyring)
}

#' @export
#' @rdname key_get

key_delete <- function(service, username = NULL, keyring = NULL) {
  assert_that(is_non_empty_string(service))
  assert_that(is_string_or_null(username))
  default_backend()$delete(service, username, keyring = keyring)
}

#' @export
#' @rdname key_get

key_list <- function(service = NULL, keyring = NULL) {
  assert_that(is_non_empty_string_or_null(service))
  default_backend()$list(service, keyring = keyring)
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
#' `has_keyring_support` checks if a backend supports multiple keyrings.
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
#' @param password The password to unlock the keyring. If not specified
#'   or `NULL`, it will be read from the console.
#'
#' @export
#' @examples
#' default_backend()
#' has_keyring_support()
#' backend_env$has_keyring_support()
#'
#' ## This might ask for a password, so we do not run it by default
#' ## It only works if the default backend supports multiple keyrings
#' \dontrun{
#' keyring_create("foobar")
#' key_set_with_value("R-test-service", "donaldduck", password = "secret",
#'                    keyring = "foobar")
#' key_get("R-test-service", "donaldduck", keyring = "foobar")
#' key_list(keyring = "foobar")
#' key_delete(keyring = "foobar")
#' }

has_keyring_support <- function() {
  default_backend()$has_keyring_support()
}

#' @export
#' @rdname has_keyring_support

keyring_create <- function(keyring) {
  assert_that(is_string(keyring))
  default_backend()$keyring_create(keyring)
}

#' @export
#' @rdname has_keyring_support

keyring_list <- function() {
  default_backend()$keyring_list()
}

#' @export
#' @rdname has_keyring_support

keyring_delete <- function(keyring) {
  assert_that(is_string(keyring))
  default_backend()$keyring_delete(keyring)
}

#' @export
#' @rdname has_keyring_support

keyring_lock <- function(keyring) {
  assert_that(is_keyring_backend(backend))
  default_backend()$keyring_lock(keyring)
}

#' @export
#' @rdname has_keyring_support

keyring_unlock <- function(keyring, password = NULL) {
  assert_that(is_string(keyring))
  default_backend()$keyring_unlock(keyring, password)
}
