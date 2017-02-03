
backend_macos <- function(keyring = "login") {
  assert_that(is_string(keyring))
  make_backend(
    name = "macos",
    keyring = keyring,
    get = backend_macos_get,
    set = backend_macos_set,
    set_with_value = backend_macos_set_with_value,
    delete = backend_macos_delete,
    list = backend_macos_list
  )
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
