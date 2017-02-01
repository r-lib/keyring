
make_backend <- function(name, ...) {
  structure(
    c(list(name = name), ...),
    class = "keyring_backend"
  )
}

check_supported <- function(backend, operation) {
  if (!is.function(backend[[operation]])) {
    stop("Backend ", sQuote(backend$name), " does not support ",
         sQuote(operation))
  }
}
