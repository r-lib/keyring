
#' Select the default backend for a platform
#'
#' 1. On Windows, the Windows Credential Store is used.
#' 1. On macOS, Keychain services are selected.
#' 1. Linux uses the Secret Service API.
#' 1. On other operating systems, secrets are stored in environment
#'   variables.
#'
#' @export
#' @name keyring backends

default_backend <- function() {
  sysname <- tolower(Sys.info()[["sysname"]])

  if (sysname == "windows") {
    backend_wincred()

  } else if (sysname == "darwin") {
    backend_macos()

  } else if (sysname == "linux") {
    backend_secret_service()

  } else {
    warning("Selecting ", sQuote(env), " backend. ",
            "Secrets are stored in environment variables")
    backend_env()
  }
}
