#' @import R6
#' @import httr2
#' @import jsonlite
#' @import openssl
#' @import RcppTOML
#' @import utils
NULL

#' SSO keyring backend for Posit Package Manager
#'
#' This backend handles the OAuth 2.0 device flow for user authentication
#' and token management with Posit Package Manager. It is designed to work
#' with `pak` for installing packages from PPM repositories that require
#' SSO authentication.
#'
#' This is a "get-only" backend. It does not support setting, deleting, or
#' listing secrets directly. The `get()` method triggers the authentication
#' flow if a valid token is not already available.
#'
#' See [backend] for the documentation of the inherited methods.
#'
#' @family keyring backends
#' @export
backend_ppm <- R6::R6Class("backend_ppm",
  inherit = backend,
  public = list(
    name = "ppm",
    ppm_url = NULL,
    service_name = NULL,
    token_file_path = NULL,
    viable = FALSE,

    #' @description Initialize the authenticator.
    initialize = function() {
      self$ppm_url <- Sys.getenv("PACKAGEMANAGER_ADDRESS", unset = NA)
      if (is.na(self$ppm_url) || self$ppm_url == "") {
        return(invisible(self))
      }

      # Basic URL parsing to get hostname:port
      parsed_url <- regmatches(self$ppm_url, regexec("^(?:https?://)?([^/]+)", self$ppm_url))[[1]]
      if (length(parsed_url) < 2) {
        return(invisible(self))
      }
      self$service_name <- parsed_url[2]
      self$token_file_path <- file.path(path.expand("~"), ".ppm", "tokens.toml")
      self$viable <- TRUE

      invisible(self)
    },

    #' @description Get the authentication token. This is the main function
    #' that triggers the authentication flow if needed.
    #' @param service The URL of the repository.
    #' @param username The username. Must be `__token__` for this backend.
    #' @param keyring The keyring name. This backend does not support multiple
    #'   keyrings, so this argument is ignored.
    #' @return A PPM access token string, or `NULL` on failure or if the
    #'   request is not applicable to this backend.
    get = function(service, username = NULL, keyring = NULL) {
      if (!self$viable || !identical(username, "__token__") || !private$.requirements_valid(service)) {
        return(NULL)
      }

      # Check for an existing, valid token
      existing_token <- private$.get_existing_token()
      if (!is.null(existing_token) && private$.can_authenticate(existing_token)) {
        return(existing_token)
      }

      # If no valid token, start the auth flow
      tryCatch({
        identity_token <- private$.get_identity_token_from_file()

        if (is.null(identity_token)) {
          identity_token <- private$.device_flow()
        }

        ppm_token <- private$.identity_to_ppm_token(identity_token)
        private$.write_token_to_file(ppm_token)

        return(ppm_token)
      }, error = function(e) {
        message("Authentication process failed: ", e$message)
        return(NULL)
      })
    },

    #' @description This backend does not support setting secrets.
    set_with_value = function(service, username = NULL, password = NULL, keyring = NULL) {
      stop("The SSO backend is for retrieving tokens and does not support setting secrets.")
    },

    #' @description This backend does not support setting secrets.
    set = function(service, username = NULL, keyring = NULL, prompt = "Password: ") {
      stop("The SSO backend is for retrieving tokens and does not support setting secrets.")
    },

    #' @description This backend does not support deleting secrets.
    delete = function(service, username = NULL, keyring = NULL) {
      stop("The SSO backend is for retrieving tokens and does not support deleting secrets.")
    },

    #' @description This backend does not support listing secrets.
    list = function(service = NULL, keyring = NULL) {
      stop("The SSO backend does not support listing secrets.")
    },

    docs = function() {
      modifyList(
        super$docs(),
        list(
          . = "Handles OAuth 2.0 device flow for Posit Package Manager."
        )
      )
    }
  ),

  private = list(
    # Check if the service URL matches the configured PPM address
    .requirements_valid = function(service) {
      startsWith(service, self$ppm_url)
    },

    # Read token from ~/.ppm/tokens.toml
    .get_existing_token = function() {
      if (!file.exists(self$token_file_path)) return(NULL)
      tryCatch({
        tokens_data <- RcppTOML::parseTOML(self$token_file_path)
        if (!is.null(tokens_data$connection)) {
            for (conn in tokens_data$connection) {
                if (identical(conn$url, self$ppm_url)) {
                    return(conn$token)
                }
            }
        }
        return(NULL)
      }, error = function(e) {
        return(NULL)
      })
    },

    # Check if a token is valid for authentication
    .can_authenticate = function(token) {
      req <- request(self$ppm_url) |>
        req_auth_bearer_token(token) |>
        req_error(is_error = \(resp) FALSE) # Handle errors manually

      resp <- req_perform(req)

      status <- resp_status(resp)
      status < 500 && status != 401 && status != 403
    },

    # Look for a pre-supplied identity token in a file
    .get_identity_token_from_file = function() {
      token_file <- Sys.getenv("PACKAGEMANAGER_IDENTITY_TOKEN_FILE", unset = NA)
      if (is.na(token_file)) return(NULL)

      tryCatch({
        trimws(readLines(token_file, n = 1, warn = FALSE))
      }, error = function(e) {
        message("Failed to read identity token file: ", e$message)
        NULL
      })
    },

    # Main OAuth 2.0 Device Flow logic
    .device_flow = function() {
      verifier <- new_pkce_verifier()
      challenge <- new_pkce_challenge(verifier)

      # 1. Initiate Device Auth
      init_url <- paste0(self$ppm_url, "/__api__/device")
      payload <- list(
        code_challenge_method = "S256",
        code_challenge = challenge
      )
      init_resp_body <- request(init_url) |>
        req_body_form(!!!payload) |>
        req_perform() |>
        resp_body_json()

      display_uri <- init_resp_body$verification_uri_complete %||% init_resp_body$verification_uri
      if (is.null(display_uri)) stop("No verification URI found in device auth response.")

      message("\nPlease open the following URL in your browser:")
      message(paste("  ", display_uri))
      message("\nAnd enter the following code when prompted:")
      message(paste("  ", init_resp_body$user_code))
      message("\nWaiting for authorization...")

      try(utils::browseURL(display_uri), silent = TRUE)

      # 2. Poll for token
      token_resp_body <- private$.complete_device_auth(
        init_resp_body$device_code,
        verifier,
        init_resp_body$interval %||% 5,
        init_resp_body$expires_in %||% 300
      )

      if (is.null(token_resp_body) || is.null(token_resp_body$id_token)) {
        stop("Failed to complete device authorization or obtain identity token.")
      }

      token_resp_body$id_token
    },

    # Polls the token endpoint until the user authenticates
    .complete_device_auth = function(device_code, verifier, interval, expires_in) {
      url <- paste0(self$ppm_url, "/__api__/device_access")
      start_time <- Sys.time()
      payload <- list(
        device_code = device_code,
        code_verifier = verifier
      )

      while (as.numeric(Sys.time() - start_time) < expires_in) {
        resp <- request(url) |>
          req_body_form(!!!payload) |>
          req_error(is_error = \(resp) FALSE) |> # Handle errors manually
          req_perform()

        status <- resp_status(resp)

        if (status == 200) {
          return(resp_body_json(resp))
        } else if (status == 400) {
          error_data <- resp_body_json(resp)
          error_code <- error_data$error
          if (error_code == "access_denied") stop("Access denied by user.")
          if (error_code == "expired_token") stop("Device authorization request expired.")
          # For "authorization_pending" or "slow_down", just wait and retry.
        } else {
          resp_raise_for_status(resp) # Raise for other unexpected errors
        }

        Sys.sleep(interval)
      }

      stop("Device authorization timed out.")
    },

    # Exchange the identity token for a final PPM access token
    .identity_to_ppm_token = function(identity_token) {
      url <- paste0(self$ppm_url, "/__api__/token")
      payload <- list(
        grant_type = "urn:ietf:params:oauth:grant-type:token-exchange",
        subject_token = identity_token,
        subject_token_type = "urn:ietf:params:oauth:token-type:id_token"
      )

      resp <- request(url) |>
        req_body_form(!!!payload) |>
        req_perform()

      token_data <- resp_body_json(resp)
      if(is.null(token_data$access_token)) stop("Failed to exchange identity token for PPM token.")

      token_data$access_token
    },

    # Write the acquired token to the ~/.ppm/tokens.toml file
    .write_token_to_file = function(token) {
      dir.create(dirname(self$token_file_path), showWarnings = FALSE, recursive = TRUE)

      new_connection <- list(url = self$ppm_url, token = token, method = "sso")

      existing_data <- if (file.exists(self$token_file_path)) {
        tryCatch(RcppTOML::parseTOML(self$token_file_path), error = function(e) list(connection = list()))
      } else {
        list(connection = list())
      }

      # Find and update existing entry or add a new one
      found <- FALSE
      if (!is.null(existing_data$connection) && length(existing_data$connection) > 0) {
        for (i in seq_along(existing_data$connection)) {
          if (identical(existing_data$connection[[i]]$url, self$ppm_url)) {
            existing_data$connection[[i]] <- new_connection
            found <- TRUE
            break
          }
        }
      }

      if (!found) {
        existing_data$connection <- c(existing_data$connection, list(new_connection))
      }

      # Manually construct TOML output
      output_lines <- c()
      for (conn in existing_data$connection) {
        output_lines <- c(
          output_lines,
          "[[connection]]",
          paste0("url = \"", conn$url, "\""),
          paste0("token = \"", conn$token, "\""),
          paste0("method = \"", conn$method, "\""),
          ""
        )
      }
      writeLines(output_lines, self$token_file_path)
    }
  )
)

#' Generate a URL-safe Base64 string
#' @param x A raw vector or string.
#' @return A URL-safe Base64 encoded string.
#' @noRd
base64url_encode <- function(x) {
  encoded <- openssl::base64_encode(x)
  # Make it URL-safe
  gsub("\\+", "-", gsub("\\/", "_", gsub("=+$", "", encoded)))
}

#' Create a new PKCE code verifier
#' @return A URL-safe PKCE code verifier string.
#' @noRd
new_pkce_verifier <- function() {
  base64url_encode(openssl::rand_bytes(32))
}

#' Create a new PKCE code challenge from a verifier
#' @param verifier The PKCE code verifier.
#' @return A URL-safe PKCE code challenge string.
#' @noRd
new_pkce_challenge <- function(verifier) {
  hash <- openssl::sha256(charToRaw(verifier))
  base64url_encode(hash)
}

# Helper for C-style `var %||% default`
`%||%` <- function(a, b) if (is.null(a)) b else a