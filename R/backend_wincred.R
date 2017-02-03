
backend_wincred <- function() {
  make_backend(
    name = "secret service",
    get = backend_wincred_get,
    set = backend_wincred_set,
    set_with_value = backend_wincred_set_with_value,
    delete = backend_wincred_delete,
    list = backend_wincred_list,
    create_keyring = backend_wincred_create
  )
}

backend_wincred_get <- function(backend, service, username) {
  .Call("keyring_wincred_get", service, username, PACKAGE = "keyring")
}

backend_wincred_set <- function(backend, service, username) {
  ps <- get_pass()
  backend_wincred_set_with_value(backend, service, username, pw)
}

backend_wincred_set_with_value <- function(backend, service,
                                           username, password) {
  .Call("keyring_wincred_set", service, username, password,
        PACKAGE = "keyring")
  invisible()
}

backend_wincred_delete <- function(backend, service, username) {
  .Call("keyring_wincred_delete", service, username, PACKAGE = "keyring")
  invisible()
}

backend_wincred_list <- function(backend, service) {
  as.data.frame(
    .Call("keyring_wincred_list", service, PACKAGE = "keyring"),
    col.names = c("service", "username"),
    stringsAsFactors = FALSE
  )
}
