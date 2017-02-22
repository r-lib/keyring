
#' Store secrets in environment variables
#'
#' This is a simple keyring backend, that stores/uses secrets in
#' environment variables of the R session.
#'
#' It does not support multiple keyrings. It also does not support listing
#' all keys, since there is no way to distinguish between keys and regular
#' environment variables.
#'
#' It does support service names and usernames: they will be separated
#' with a `:` character in the name of the environment variable.
#'
#' @family keyring backends
#' @export
#' @examples
#' \dontrun{
#' env <- backend_env()
#' key_set("r-keyring-test", username = "donaldduck", backend = env)
#' key_get("r-keyring-test", username = "donaldduck", backend = env)
#' Sys.getenv("r-keyring-test:donaldduck")
#'
#' # This is an error
#' key_list(backend = env)
#'
#' # Clean up
#' key_delete("r-keyring-test", username = "donaldduck", backend = env)
#' }

backend_env <- function() {
  make_backend(
    name = "env",
    get = backend_env_get,
    set = backend_env_set,
    delete = backend_env_delete,
    set_with_value = backend_env_set_with_value,
    list = NULL
  )
}

backend_env_get <- function(backend, service, username) {
  var <- backend_env_to_var(service, username)
  res <- Sys.getenv(var, NA_character_)
  if (is.na(res)) stop("Cannot find password")
  res
}

backend_env_set <- function(backend, service, username) {
  pw <- get_pass()
  backend_env_set_with_value(backend, service, username, pw)
}

backend_env_set_with_value <- function(backend, service, username, password) {
  var <- backend_env_to_var(service, username)
  do.call(Sys.setenv, structure(list(password), names = var))
  invisible()
}

backend_env_delete <- function(backend, service, username) {
  var <- backend_env_to_var(service, username)
  Sys.unsetenv(var)
}

backend_env_to_var <- function(service, username) {
  if (is.null(username)) {
    service
  } else {
    paste0(service, ":", username)
  }
}
