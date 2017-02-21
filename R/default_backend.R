
#' Select the default backend and default keyring
#'
#' The default backend is selected
#' 1. based on the `keyring_backend` option. See [base::options()].
#'    This can be set currently to `"env"`, `"macos"`, `"wincred"` or
#'    `"secret_service"`.
#' 1. If this is not set, then the `R_KEYRING_BACKEND` environment variable
#'    is checked.
#' 1. If this is not set, either, then the backend is selected
#'    automatically, based on the OS:
#'    1. On Windows, the Windows Credential Store (`"wincred"`) is used.
#'    1. On macOS, Keychain services are selected (`"macos"`).
#'    1. Linux uses the Secret Service API (`"secret_service"`).
#'    1. On other operating systems, secrets are stored in environment
#'       variables (`"env"`).
#'
#' Most backends support multiple keyrings. For these the keyring is
#' selected from
#' 1. the `keyring_keyring` option.
#' 1. If this is not set, the `R_KEYRING_KEYRING` environment variable.
#' 1. If this is not set, then the OS default keyring is selected.
#'    Usually this keyring is automatically unlocked when the user logs in.
#'
#' @export
#' @name keyring backends

default_backend <- function() {
  backend <- getOption("keyring_backend", "")
  if (identical(backend, "")) backend <- default_backend_env_or_auto()

  ## Is it just a backend name?
  if (is_string(backend)) backend <- backend_factory(backend)

  ## At this point 'backend' is a backend constructor
  ## Check if a specific keyring is requested
  keyring <- getOption(
    "keyring_keyring",
    Sys.getenv("R_KEYRING_KEYRING", "")
  )
  if (nzchar(keyring)) {
    backend(keyring = keyring)
  } else {
    backend()
  }
}

default_backend_env_or_auto <- function() {
  backend <- Sys.getenv("R_KEYRING_BACKEND", "")
  if (identical(backend, "")) backend <- default_backend_auto()
  backend
}

default_backend_auto <- function() {
  sysname <- tolower(Sys.info()[["sysname"]])

  if (sysname == "windows") {
    backend_wincred

  } else if (sysname == "darwin") {
    backend_macos

  } else if (sysname == "linux") {
    backend_secret_service

  } else {
    warning("Selecting ", sQuote("env"), " backend. ",
            "Secrets are stored in environment variables")
    backend_env
  }
}

backend_factory <- function(name) {
  assert_that(is_string(name))
  if (name %in% names(known_backends)) return(known_backends[[name]])
  stop("Unknown backend: ", sQuote(name))
}

known_backends <- list(
  "wincred" = backend_wincred,
  "macos" = backend_macos,
  "secret_service" = backend_secret_service,
  "env" = backend_env
)
