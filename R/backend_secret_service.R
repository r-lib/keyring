
#' Create a Secret Service keyring backend
#'
#' This backend is the default on Linux. It uses the libsecret library,
#' and needs a secret service daemon running (e.g. Gnome Keyring, or
#' KWallet). It uses DBUS to communicate with the secret service daemon.
#'
#' This backend supports multiple keyrings
#'
#' @param keyring Name of the keyring to use. `NULL` specifies the
#'   default keyring.
#' @return A backend object that can be used in `keyring` functions.
#'
#' @family keyring backends
#' @export

backend_secret_service <- function(keyring = NULL) {
  assert_that(is_string_or_null(keyring))
  make_backend(
    name = "secret service",
    keyring = keyring,
    get = backend_secret_service_get,
    set = backend_secret_service_set,
    set_with_value = backend_secret_service_set_with_value,
    delete = backend_secret_service_delete,
    list = backend_secret_service_list,
    create_keyring = backend_secret_service_create_keyring,
    list_keyring = backend_secret_service_list_keyring,
    delete_keyring = backend_secret_service_delete_keyring,
    lock_keyring = backend_secret_service_lock_keyring,
    unlock_keyring = backend_secret_service_unlock_keyring,
    is_available = backend_secret_service_is_available
  )
}

backend_secret_service_get <- function(backend, service, username) {
  .Call("keyring_secret_service_get", backend$keyring, service, username,
        PACKAG = "keyring")
}

backend_secret_service_set <- function(backend, service, username) {
  pw <- get_pass()
  backend_secret_service_set_with_value(backend, service, username, pw)
}

backend_secret_service_set_with_value <- function(backend, service,
                                                  username, password) {
  .Call("keyring_secret_service_set", backend$keyring, service, username, password,
        PACKAGE = "keyring")
  invisible()
}

backend_secret_service_delete <- function(backend, service, username) {
  .Call("keyring_secret_service_delete", backend$keyring, service, username,
        PACKAGE = "keyring")
  invisible()
}

backend_secret_service_list <- function(backend, service) {
  res <- .Call("keyring_secret_service_list", backend$keyring, service,
               PACKAGE = "keyring")
  data.frame(
    service = res[[1]],
    username = res[[2]],
    stringsAsFactors = FALSE
  )
}

backend_secret_service_create_keyring <- function(backend) {
  password <- get_pass()
  backend_secret_service_create_keyring_direct(backend, password)
}

backend_secret_service_create_keyring_direct <- function(keyring, password) {
  .Call("keyring_secret_service_create_keyring", keyring, password,
        PACKAGE = "keyring")
  invisible()
}

backend_secret_service_list_keyring <- function(backend) {
  res <- .Call("keyring_secret_service_list_keyring", PACKAGE = "keyring")
  data.frame(
    keyring = res[[1]],
    num_secrets = res[[2]],
    locked = res[[3]],
    stringsAsFactors = FALSE
  )
}

backend_secret_service_delete_keyring <- function(backend) {
  .Call("keyring_secret_service_delete_keyring", backend$keyring,
        PACKAGE = "keyring")
  invisible()
}

backend_secret_service_lock_keyring <- function(backend) {
  .Call("keyring_secret_service_lock_keyring", backend$keyring, PACKAGE = "keyring")
  invisible()
}

backend_secret_service_unlock_keyring <- function(backend, password = NULL) {
  if (is.null(password)) password <- get_pass()
  .Call("keyring_secret_service_unlock_keyring", backend$keyring, password,
        PACKAGE = "keyring")
  invisible()
}

backend_secret_service_is_available <- function(report_error = FALSE) {
  .Call("keyring_secret_service_is_available", report_error, PACKAGE = "keyring")
}