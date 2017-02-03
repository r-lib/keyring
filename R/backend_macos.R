
backend_macos <- function(keyring = NULL) {
  assert_that(is_string_or_null(keyring))
  make_backend(
    name = "macos",
    keyring = backend_macos_keyring_file(keyring),
    get = backend_macos_get,
    set = backend_macos_set,
    set_with_value = backend_macos_set_with_value,
    delete = backend_macos_delete,
    list = backend_macos_list,
    create_keyring = backend_macos_create
  )
}

backend_macos_keyring_file <- function(name) {
  if (is.null(name)) {
    name

  } else if (substr(name, 1, 1) == "/" || substr(name, 1, 2) == "./") {
    normalizePath(name, mustWork = FALSE)

  } else {
    normalizePath(
      paste0("~/Library/Keychains/", name, ".keychain"),
      mustWork = FALSE
    )
  }
}

backend_macos_get <- function(backend, service, username) {
  .Call("keyring_macos_get", backend$keyring, service, username,
        PACKAGE = "keyring")
}

backend_macos_set <- function(backend, service, username) {
  pw <- get_pass()
  backend_macos_set_with_value(backend, service, username, pw)
}

backend_macos_set_with_value <- function(backend, service, username,
                                         password) {
  .Call("keyring_macos_set", backend$keyring, service, username, password,
        PACKAGE = "keyring")
  invisible()
}

backend_macos_delete <- function(backend, service, username) {
  .Call("keyring_macos_delete", backend$keyring, service, username,
        PACKAGE = "keyring")
  invisible()
}

backend_macos_list <- function(backend, service) {
  as.data.frame(
    .Call("keyring_macos_list", backend$keyring, service,
          PACKAGE = "keyring"),
    col.names = c("service", "username"),
    stringsAsFactors = FALSE
  )
}

backend_macos_create <- function(backend, pw = NULL) {
  assert_that(is_string_or_null(pw))
  if (is.null(pw)) pw <- get_pass()
  .Call("keyring_macos_create", backend$keyring, pw, PACKAGE = "keyring")
  invisible()
}
