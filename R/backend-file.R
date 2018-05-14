
keyrings <- new.env()

#' Store secrets in encrypted files
#'
#' This is a simple keyring backend, that stores/uses secrets in encrypted
#' files.
#'
#' It supports multiple keyrings.
#'
#' See [backend] for the documentation of the individual methods.
#'
#' @family keyring backends
#' @export
#' @include backend-class.R
#' @examples
#' \dontrun{
#' kb <- backend_file$new()
#' }

backend_file <- R6Class(
  "backend_file",
  inherit = backend_keyrings,
  public = list(
    name = "file",
    initialize = function(keyring = NULL)
      b_file_init(self, private, keyring),

    get = function(service, username = NULL, keyring = NULL)
      b_file_get(self, private, service, username, keyring),
    set = function(service, username = NULL, keyring = NULL)
      b_file_set(self, private, service, username, keyring),
    set_with_value = function(service, username = NULL, password = NULL,
      keyring = NULL)
      b_file_set_with_value(self, private, service, username, password,
                            keyring),
    list = function(service = NULL, keyring = NULL)
      b_file_list(self, private, service, keyring),

    keyring_create = function(keyring)
      b_file_keyring_create(self, private, keyring),
    keyring_delete = function(keyring = NULL)
      b_file_keyring_delete(self, private, keyring),

    keyring_lock = function(keyring = NULL)
      b_file_keyring_lock(self, private, keyring),
    keyring_unlock = function(keyring = NULL, password = NULL)
      b_file_keyring_unlock(self, private, keyring, password),
    keyring_is_locked = function(keyring = NULL)
      b_file_keyring_is_locked(self, private, keyring),

    keyring_default = function()
      b_file_keyring_default(self, private),
    keyring_set_default = function(keyring)
      b_file_keyring_set_default(self, private, keyring)
  ),

  private = list(
    keyring = NULL,

    keyring_create_direct = function(keyring = NULL, password = NULL,
      nonce = NULL, items = NULL)
      b_file_keyring_create_direct(self, private, keyring, password, nonce,
        items),

    keyring_file = function(keyring = NULL, ...)
      b_file_keyring_file(self, private, keyring, ...),
    keyring_read_file = function(keyring = NULL)
      b_file_read_keyring_file(self, private, keyring),
    keyring_write_file = function(keyring = NULL, nonce = NULL, items = NULL,
      key = NULL)
      b_file_write_keyring_file(self, private, keyring, nonce, items, key),

    key_get = function(keyring = NULL)
      b_file_key_get(self, private, keyring),
    key_set = function(key = NULL, keyring = NULL)
      b_file_key_set(self, private, key, keyring),
    key_unset = function(keyring = NULL)
      b_file_key_unset(self, private, keyring),
    key_is_set = function(keyring = NULL)
      b_file_key_is_set(self, private, keyring),

    keyring_set = function(keyring = NULL, nonce = NULL, check = NULL,
      items = NULL)
      b_file_keyring_set(self, private, keyring, nonce, check, items),
    keyring_get = function(keyring = NULL)
      b_file_keyring_get(self, private, keyring),
    nonce_get = function(keyring = NULL)
      b_file_nonce_get(self, private, keyring),
    items_get = function(keyring = NULL)
      b_file_items_get(self, private, keyring),
    check_get = function(keyring = NULL)
      b_file_check_get(self, private, keyring)
  )
)

b_file_init <- function(self, private, keyring) {
  self$keyring_set_default(keyring %||% "~/.keyring")

  invisible(self)
}

b_file_get <- function(self, private, service, username, keyring) {

  if (self$keyring_is_locked(keyring))
    self$keyring_unlock(keyring)

  all_items <- private$items_get(keyring)
  item_matches <- sapply(all_items, `[[`, "service_name") %in% service

  if (!is.null(username)) {
    item_matches <- item_matches &
                      sapply(all_items, `[[`, "user_name") %in% username
  }

  if (sum(item_matches) < 1L)
    b_file_error("cannot get secret",
                 "The specified item could not be found in the keychain.")

  sapply(
    lapply(all_items[item_matches], `[[`, "secret"),
    b_file_secret_decrypt,
    private$nonce_get(keyring),
    private$key_get(keyring)
  )
}

b_file_set <- function(self, private, service, username, keyring) {

  if (self$keyring_is_locked(keyring))
    self$keyring_unlock(keyring)

  password <- get_pass()

  self$set_with_value(service, username, password, keyring)

  invisible(self)
}

b_file_set_with_value <- function(self, private, service, username,
                                  password, keyring) {

  if (self$keyring_is_locked(keyring))
    self$keyring_unlock(keyring)

  all_items <- private$items_get(keyring)

  is_duplicate <- any(sapply(all_items, `[[`, "service_name") %in% service &
                        sapply(all_items, `[[`, "user_name") %in% username)

  if (is_duplicate)
    b_file_error("cannot save secret",
                 "The specified item is already in the keychain.")

  new_item <- list(
    service_name = service,
    user_name = username,
    secret = b_file_secret_encrypt(
      password,
      private$nonce_get(keyring),
      private$key_get(keyring)
    )
  )

  private$keyring_set(keyring, items = c(all_items, list(new_item)))
  private$keyring_write_file(keyring)

  invisible(self)
}

b_file_list <- function(self, private, service, keyring) {

  all_items <- private$items_get(keyring)

  res <- data.frame(
    service = sapply(all_items, `[[`, "service_name"),
    username = sapply(all_items, `[[`, "user_name"),
    stringsAsFactors = FALSE
  )

  if (!is.null(service))
    res[res[["service"]] == service, ]
  else
    res
}

b_file_keyring_create <- function(self, private, keyring)
  private$keyring_create_direct(keyring)

b_file_keyring_delete <- function(self, private, keyring) {

  if (self$keyring_is_locked(keyring))
    self$keyring_unlock(keyring)

  unlink(private$keyring_file(keyring))

  invisible(self)
}

b_file_keyring_lock <- function(self, private, keyring) {

  assert_that(file.exists(private$keyring_file(keyring)))

  private$key_unset(keyring)

  invisible(self)
}

b_file_keyring_unlock <- function(self, private, keyring, password) {

  private$key_set(password, keyring)

  assert_that(file.exists(private$keyring_file(keyring)))

  if (self$keyring_is_locked(keyring)) {
    private$key_unset(keyring)
    b_file_error("failed to unlock keyring")
  }

  invisible(self)
}

b_file_keyring_is_locked <- function(self, private, keyring) {

  keyring <- keyring %||% private$keyring

  if (!file.exists(keyring) || !private$key_is_set(keyring)) {
    TRUE
  } else {
    tryCatch(
      {
        b_file_secret_decrypt(
          private$check_get(keyring),
          private$nonce_get(keyring),
          private$key_get(keyring)
        )
        FALSE
      },
      error = function(e) {
        if(conditionMessage(e) == "Failed to decrypt")
          TRUE
        else
          signalCondition(e)
      }
    )
  }
}

b_file_keyring_default <- function(self, private) {
  private$keyring
}

b_file_keyring_set_default <- function(self, private, keyring) {
  private$keyring <- keyring
  invisible(self)
}

## --------------------------------------------------------------------
## Private

b_file_keyring_create_direct <- function(self, private, keyring, password,
  nonce, items) {

  file_name <- keyring %||% private$keyring

  if (file.exists(file_name))
    confirmation(paste("are you sure you want to overwrite", file_name))

  private$keyring_write_file(
    file_name,
    nonce %||% sodium::random(24L),
    items %||% list(),
    password %||% get_pass()
  )

  invisible(self)
}

b_file_keyring_file <- function(self, private, keyring, ...) {

  file_name <- keyring %||% private$keyring

  assert_that(is_string(file_name))

  if (!file.exists(file_name))
    private$keyring_create_direct(file_name, ...)

  normalizePath(file_name, mustWork = TRUE)
}

b_file_read_keyring_file <- function(self, private, keyring) {

  yml <- yaml::yaml.load_file(keyring %||% private$keyring)

  assert_that(is.list(yml),
              assertthat::has_name(yml, "keyring_info"),
              is.list(yml[["keyring_info"]]),
              assertthat::has_name(yml[["keyring_info"]], "nonce"),
              assertthat::has_name(yml[["keyring_info"]], "integrity_check"),
              assertthat::has_name(yml, "items"),
              is.list(yml[["items"]]))

  list(
    nonce = sodium::hex2bin(yml[["keyring_info"]][["nonce"]]),
    items = yml[["items"]],
    check = yml[["keyring_info"]][["integrity_check"]]
  )
}

b_file_write_keyring_file <- function(self, private, keyring, nonce, items,
  key) {

  nonce <- nonce %||% private$nonce_get(keyring)

  yaml::write_yaml(
    list(
      keyring_info = list(
        keyring_version = as.character(
          utils::packageVersion(methods::getPackageName())
        ),
        nonce = sodium::bin2hex(nonce),
        integrity_check = b_file_secret_encrypt(
          paste(sample(letters, 22L, replace = TRUE), collapse = ""),
          nonce,
          key %||% private$key_get(keyring)
        )
      ),
      items = items %||% private$items_get(keyring)
    ),
    keyring %||% private$keyring
  )

  invisible(self)
}

b_file_key_get <- function(self, private, keyring) {

  kr_env <- b_file_keyring_env(private$keyring_file(keyring))

  if (is.null(kr_env$key))
    key <- private$key_set(keyring = keyring)
  else
    key <- kr_env$key

  assert_that(is.raw(key), length(key) > 0L)

  key
}

b_file_key_unset <- function(self, private, keyring) {

  kr_env <- b_file_keyring_env(private$keyring_file(keyring))

  kr_env$key <- NULL

  invisible(kr_env)
}

b_file_key_is_set <- function(self, private, keyring)
  !is.null(b_file_keyring_env(private$keyring_file(keyring))$key)


b_file_key_set <- function(self, private, key, keyring) {

  key <- key %||% get_pass()
  assert_that(is_string(key))
  key <- sodium::hash(charToRaw(key))

  kr_env <- b_file_keyring_env(private$keyring_file(keyring, password = key))

  kr_env$key <- key
}

b_file_keyring_set <- function(self, private, keyring, nonce, check, items) {

  kr_env <- b_file_keyring_env(private$keyring_file(keyring))

  if (is.null(nonce) || is.null(check) || is.null(items))
    kr <- private$keyring_read_file(keyring)

  nonce <- nonce %||% kr[["nonce"]]
  assert_that(is.raw(nonce), length(nonce) > 0L)
  kr_env$nonce <- nonce

  check <- check %||% kr[["check"]]
  assert_that(is.character(check), length(check) > 0L)
  kr_env$check <- check

  kr_env$items <- lapply(items %||% kr[["items"]], b_file_validate_item)

  kr_env
}

b_file_keyring_get <- function(self, private, keyring)
  list(
    nonce = private$nonce_get(keyring),
    items = private$items_get(keyring),
    check = private$check_get(keyring)
  )

b_file_nonce_get <- function(self, private, keyring) {

  kr_env <- b_file_keyring_env(private$keyring_file(keyring))

  if (is.null(kr_env$nonce))
    kr_env <- private$keyring_set(keyring)

  res <- kr_env$nonce
  assert_that(is.raw(res), length(res) > 0L)

  res
}

b_file_items_get <- function(self, private, keyring) {

  kr_env <- b_file_keyring_env(private$keyring_file(keyring))

  if (is.null(kr_env$items))
    private$keyring_set(keyring)

  lapply(kr_env$items, b_file_validate_item)
}

b_file_check_get <- function(self, private, keyring) {

  kr_env <- b_file_keyring_env(private$keyring_file(keyring))

  if (is.null(kr_env$check))
    private$keyring_set(keyring)

  res <- kr_env$check
  assert_that(is.character(res), length(res) > 0L)

  res
}

## --------------------------------------------------------------------
## helper functions

b_file_secret_encrypt <- function(secret, nonce, key) {

  res <- sodium::data_encrypt(
    charToRaw(secret),
    key,
    nonce
  )

  b_file_split_string(sodium::bin2hex(res))
}

b_file_secret_decrypt <- function(secret, nonce, key)
  rawToChar(
    sodium::data_decrypt(
      sodium::hex2bin(b_file_merge_string(secret)),
      key,
      nonce
    )
  )

b_file_keyring_env <- function(keyring) {

  env_name <- normalizePath(keyring, mustWork = TRUE)

  kr_env <- get0(env_name, envir = keyrings, mode = "environment")

  if (is.null(kr_env))
    kr_env <- assign(env_name, new.env(), envir = keyrings)

  kr_env
}

b_file_error <- function(problem, reason = NULL) {
  info <- if (is.null(reason))
    problem
  else
    paste0(problem, ": ", reason)
  stop("keyring error (file-based keyring), ", info, call. = FALSE)
}

b_file_validate_item <- function(item) {

  assert_that(is.list(item), length(item) == 3L,
              assertthat::has_name(item, "service_name"),
              is_string(item[["service_name"]]),
              assertthat::has_name(item, "user_name"),
              is_string_or_null(item[["user_name"]]),
              assertthat::has_name(item, "secret"),
              is.raw(item[["secret"]]) || is_string(item[["secret"]]))

  invisible(item)
}

b_file_split_string <- function(string, width = 78L) {
  assert_that(is_string(string))
  paste(
    lapply(
      seq.int(ceiling(nchar(string) / width)) - 1L,
      function(x) substr(string, x * width + 1L, x * width + width)
    ),
    collapse = "\n"
  )
}

b_file_merge_string <- function(string) {
  assert_that(is_string(string))
  paste(strsplit(string, "\n")[[1L]], collapse = "")
}
