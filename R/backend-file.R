
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
    keyring_create = function(keyring = NULL, nonce = NULL, items = NULL)
      b_file_keyring_create(self, private, keyring, nonce, items),
    keyring_default = function()
      b_file_keyring_default(self, private),
    keyring_set_default = function(keyring)
      b_file_keyring_set_default(self, private, keyring)
  ),

  private = list(
    keyring = NULL,
    key = NULL,
    nonce = NULL,
    items = NULL,
    keyring_file = function(name = NULL)
      b_file_keyring_file(self, private, name),
    keyring_read_file = function(name = NULL)
      b_file_read_keyring_file(self, private, name),
    keyring_write_file = function(name = NULL, nonce = NULL, items = NULL)
      b_file_write_keyring_file(self, private, name, nonce, items),
    keyring_set = function(keyring = NULL)
      b_file_keyring_set(self, private, keyring),
    keyring_get = function()
      b_file_keyring_get(self, private),
    key_get = function()
      b_file_key_get(self, private),
    key_set = function(key = NULL)
      b_file_key_set(self, private, key),
    nonce_get = function(keyring = NULL)
      b_file_nonce_get(self, private, keyring),
    nonce_set = function(nonce = NULL)
      b_file_nonce_set(self, private, nonce),
    items_get = function(keyring = NULL)
      b_file_items_get(self, private, keyring),
    items_set = function(items = NULL)
      b_file_items_set(self, private, items),
    secret_encrypt = function(secret, nonce = NULL, key = NULL)
      b_file_secret_encrypt(self, private, secret, nonce, key),
    secret_decrypt = function(secret, nonce = NULL, key = NULL)
      b_file_secret_decrypt(self, private, secret, nonce, key)
  )
)

b_file_init <- function(self, private, keyring) {
  self$keyring_set_default(keyring %||% "~/.keyring")
  invisible(self)
}

b_file_get <- function(self, private, service, username, keyring) {

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
    private$secret_decrypt
  )
}

b_file_set <- function(self, private, service, username, keyring) {
  password <- get_pass()
  self$set_with_value(service, username, password, keyring)
  invisible(self)
}

b_file_set_with_value <- function(self, private, service, username,
                                  password, keyring) {

  all_items <- private$items_get(keyring)

  is_duplicate <- any(sapply(all_items, `[[`, "service_name") %in% service &
                        sapply(all_items, `[[`, "user_name") %in% username)

  if (is_duplicate)
    b_file_error("cannot save secret",
                 "The specified item is already in the keychain.")

  new_item <- list(
    service_name = service,
    user_name = username,
    secret = private$secret_encrypt(password)
  )

  private$items_set(c(all_items, list(new_item)))
  private$keyring_write_file(keyring)

  invisible(self)
}

b_file_keyring_create <- function(self, private, keyring, nonce, items) {

  file_name <- keyring %||% private$keyring

  if (file.exists(file_name))
    confirmation(paste("are you sure you want to overwrite", file_name))

  private$keyring_write_file(
    file_name,
    nonce %||% sodium::random(24L),
    items %||% list()
  )

  invisible(self)
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

b_file_keyring_file <- function(self, private, name) {

  file_name <- name %||% private$keyring

  assert_that(is_string(file_name))

  if (!file.exists(file_name))
    self$keyring_create(file_name)

  normalizePath(file_name)
}

b_file_read_keyring_file <- function(self, private, name) {

  file_name <- private$keyring_file(name)

  assert_that(file.exists(file_name))

  yml <- yaml::yaml.load_file(file_name)

  list(
    nonce = sodium::hex2bin(yml[["keyring_info"]][["nonce"]]),
    items = yml[["items"]]
  )
}

b_file_write_keyring_file <- function(self, private, keyring, nonce, items) {

  nonce <- nonce %||% private$nonce

  if (is.raw(nonce))
    nonce <- sodium::bin2hex(nonce)

  yaml::write_yaml(
    list(
      keyring_info = list(
        keyring_version = as.character(
          utils::packageVersion(methods::getPackageName())
        ),
        nonce = nonce
      ),
      items = items %||% private$items
    ),
    keyring %||% private$keyring
  )

  invisible(self)
}

b_file_keyring_set <- function(self, private, keyring) {
  kr <- private$keyring_read_file(keyring)
  private$nonce_set(kr[["nonce"]])
  private$items_set(kr[["items"]])
}

b_file_keyring_get <- function(self, private) {
  list(
    nonce = private$nonce_get(),
    items = private$items_get()
  )
}

b_file_key_get <- function(self, private) {

  if (is.null(private$key))
    private$key_set()

  key <- private$key

  assert_that(is.raw(key), length(key) > 0L)

  key
}

b_file_key_set <- function(self, private, key) {

  key <- key %||% get_pass()
  assert_that(is_string(key))

  private$key <- sodium::hash(charToRaw(key))

  invisible(self)
}

b_file_nonce_get <- function(self, private, keyring) {

  if (!is.null(keyring)) {
    res <- private$keyring_read_file(keyring)[["nonce"]]
  } else {
    if (is.null(private$nonce))
      private$nonce_set()
    res <- private$nonce
  }

  assert_that(is.raw(res), length(res) > 0L)

  res
}

b_file_nonce_set <- function(self, private, nonce) {

  nonce <- nonce %||% private$keyring_read_file()[["nonce"]]
  assert_that(is.raw(nonce), length(nonce) > 0L)

  private$nonce <- nonce

  invisible(self)
}

b_file_items_get <- function(self, private, keyring) {

  if (!is.null(keyring)) {
    items <- private$keyring_read_file(keyring)[["items"]]
  } else {
    if (is.null(private$items))
      private$items_set()
    items <- private$items
  }

  lapply(items, b_file_check_item)
}

b_file_items_set <- function(self, private, items) {

  private$items <- lapply(
    items %||% private$keyring_read_file()[["items"]],
    b_file_check_item
  )

  invisible(self)
}

b_file_secret_encrypt <- function(self, private, secret, nonce, key) {

  res <- sodium::data_encrypt(
    charToRaw(secret),
    key %||% private$key_get(),
    nonce %||% private$nonce_get()
  )

  b_file_split_string(sodium::bin2hex(res))
}

b_file_secret_decrypt <- function(self, private, secret, nonce, key) {
  rawToChar(
    sodium::data_decrypt(
      sodium::hex2bin(paste(secret, collapse = "")),
      key %||% private$key_get(),
      nonce %||% private$nonce_get()
    )
  )
}

## --------------------------------------------------------------------
## helper functions

b_file_error <- function(problem, reason = NULL) {
  info <- if (is.null(reason))
    problem
  else
    paste0(problem, ": ", reason)
  stop("keyring error (file-based keyring), ", info, call. = FALSE)
}

b_file_check_item <- function(item) {

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