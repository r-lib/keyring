
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
#' @include backend-class.R
#' @examples
#' \dontrun{
#' env <- backend_env$new()
#' env$set("r-keyring-test", username = "donaldduck")
#' env$get("r-keyring-test", username = "donaldduck")
#' Sys.getenv("r-keyring-test:donaldduck")
#'
#' # This is an error
#' env$list(backend = env)
#'
#' # Clean up
#' env$delete("r-keyring-test", username = "donaldduck")
#' }

backend_env <- R6Class(
  "backend_env",
  inherit = backend,
  public = list(
    get = function(service, username = NULL)
      b_env_get(self, private, service, username),
    set = function(service, username = NULL)
      b_env_set(self, private, service, username),
    set_with_value = function(service, username = NULL, password = NULL)
      b_env_set_with_value(self, private, service, username, password),
    delete = function(service, username)
      b_env_delete(self, private, service, username)
  ),
  private = list(
    env_to_var = function(service, username) {
      b_env_env_to_var(self, private, service, username)
    }
  )
)

b_env_get <- function(self, private, service, username) {
  var <- private$env_to_var(service, username)
  res <- Sys.getenv(var, NA_character_)
  if (is.na(res)) stop("Cannot find password")
  res  
}

b_env_set <- function(self, private, service, username) {
  password <- get_pass()
  b_env_set_with_value(self, private, service, username, password)
}

b_env_set_with_value <- function(self, private, service, username,
                                 password) {
  var <- private$env_to_var(service, username)
  do.call(Sys.setenv, structure(list(password), names = var))
  invisible()
}

b_env_delete <- function(self, private, service, username) {
  var <- private$env_to_var(service, username)
  Sys.unsetenv(var)
}

b_env_env_to_var <- function(self, private, service, username) {
  if (is.null(username)) {
    service
  } else {
    paste0(service, ":", username)
  }
}
