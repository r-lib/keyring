
## The windows credential store does not support multiple keyrings,
## so we emulate them.
##
## For every (non-default) keyring, we create a credential, with target name
## "keyring::". This credential contains metadata about the keyring. It currently
## has the following (DCF) format:
##
## Version: 1.0.0
## Verify: NgF+vkkNsOoSnXVXt249u6xknskhDasMIhE8Uuzpl/w=
## Salt: some random salt
##
## The verify tag is used to check if the keyring password that was specified to
## unlock the keyring, was correct.
##
## The Salt tag is used to salt the SHA256 hash, to make it more secure.
## It is generated randomly when the keyring is created.
##
## When a keyring is unlocked, the user specifies the pass phrase of the
## keyring. We create the SHA256 hash of this pass phrase, and this will be the
## AES key to encrypt/decrypt the items (keys) in the keyring. When unlocking a
## keyring, we use the 'Verify' field, to see if the supplied password indeed
## hashes to the correct AES key. If it can decrypt the verify string, then it
## is correct.
##
## We also store the AES key in the keyring, in a session credential with
## target name "keyring::unlocked". A session credential's life time is the
## life time of a single login session. The AES key is stored in a base64
## encoded form, e.g.:
##
## JvL7srqc0X1vVnqbSayFnIkJZoe2xMOWoDh+aBR9DJc=
##
## The credentials of the keyring itself have target names as
## "keyring:service:username", where the username may be empty.
## If keyring is empty, then the credential is considered to be
## on the default keyring, and it is not encrypted. Credentials on
## other keyrings are encrypted using the AES key of the keyring.
## The random initialization vector of the encryption is stored as the
## first 16 bytes of the keyring item.
##
## When we 'set' a key, we need to:
## 1. Check if the key is on the default keyring.
## 2. If 1. is TRUE, then just set the key, using target name
##    ":service:username" (username might be empty, servicename not),
##    and finish.
## 3. Check if the keyring exists.
## 4. If 3. is FALSE, then error and finish.
## 5. Check that the keyring is unlocked.
## 6. If 5. is FALSE, then prompt the user and unlock the keyring.
## 7. Encrypt the key with the AES key, and store the encrypted
##    key using target name "keyring:service:username" (again, username
##    might be empty, service name not).
##
## When we 'get' a key, we need to:
## 1. Check if the key is on the default keyring.
## 2. If 1. is TRUE, then we just get the key, using target name
##    ":service:username".
## 3. Check if the keyring is locked.
## 4. If 3. is TRUE, then prompt the user and unlock the keyring.
## 5. Get the AES key from the unlocked keyring.
## 6. Get the key and use the AES key to decrypt it.
##
## To unlock a keyring we need to:
## 1. Get the keyring password and SHA256 hash it.
## 2. Store the
## 2. Read the private RSA key, and decrypt the encrypted AES key with it.
## 3. Store the AES key under target name keyring::unlocked.
##
## The C functions for the wincred backend do not know about multiple
## keyrings at all, we just use them to get/set/delete/list "regular"
## credentials in the credential store.

b_wincred_protocol_version <- "1.0.0"

## This is a low level API

b_wincred_i_get <- function(target) {
  .Call("keyring_wincred_get", target, PACKAGE = "keyring")
}

b_wincred_i_set <- function(target, password, username = NULL,
		                  session = FALSE) {
  .Call("keyring_wincred_set", target, password, username, session,
        PACKAGE = "keyring")
}

b_wincred_i_delete <- function(target) {
  .Call("keyring_wincred_delete", target, PACKAGE = "keyring")
}

b_wincred_i_exists <- function(target) {
  .Call("keyring_wincred_exists", target, PACKAGE = "keyring")
}

b_wincred_i_enumerate <- function(filter) {
  .Call("keyring_wincred_enumerate", filter, PACKAGE = "keyring")
}

#' @importFrom utils URLencode

b_wincred_i_escape <- function(x) {
  URLencode(x, reserved = TRUE, repeated = TRUE)
}

#' @importFrom utils URLdecode

b_wincred_i_unescape <- function(x) {
  URLdecode(x)
}

b_wincred_target <- function(keyring, service, username) {
  keyring <- if (is.null(keyring)) "" else b_wincred_i_escape(keyring)
  service <- b_wincred_i_escape(service)
  username <- if (is.null(username)) "" else b_wincred_i_escape(username)
  paste0(keyring, ":", service, ":", username)
}

## For the username we need a workaround, because
## strsplit("foo::")[[1]] gives c("foo", ""), i.e. the third empty element
## is cut off.

b_wincred_i_parse_target <- function(target) {
  parts <- lapply(strsplit(target, ":"), lapply, b_wincred_i_unescape)
  res <- data.frame(
    stringsAsFactors = FALSE,
    keyring = vapply(parts, "[[", "", 1),
    service = vapply(parts, "[[", "", 2),
    username = vapply(parts, function(x) x[3][[1]] %||% "", "")
  )
}

b_wincred_target_keyring <- function(keyring) {
  b_wincred_target(keyring, "", "")
}

b_wincred_target_lock <- function(keyring) {
  b_wincred_target(keyring, "", "unlocked")
}

b_wincred_parse_keyring_credential <- function(target) {
  value <- b_wincred_i_get(target)
  con <- textConnection(value)
  on.exit(close(con), add = TRUE)
  as.list(read.dcf(con)[1,])
}

b_wincred_write_keyring_credential <- function(target, data) {
  con <- textConnection(NULL, open = "w")
  mat <- matrix(unlist(data), nrow = 1)
  colnames(mat) <- names(data)
  write.dcf(mat, con)
  value <- paste0(paste(textConnectionValue(con), collapse = "\n"), "\n")
  close(con)
  b_wincred_i_set(target, password = value)
}

#' @importFrom openssl base64_decode
#' @importFrom utils head tail

b_wincred_get_encrypted_aes <- function(str) {
  r <- base64_decode(str)
  structure(tail(r, -16), iv = head(r, 16))
}

## 1. Try to get the unlock credential
## 2. If it exists, return AES key
## 3. If not, then get the credential of the keyring
## 4. Ask for the keyring password
## 5. Hash the password to get the AES key
## 6. Verify that the AES key is correct, using the Verify field of
##    the keyring credential
## 7. Create a SESSION credential, with the decrypted AES key
## 8. Return the decrypted AES key

#' @importFrom openssl sha256 aes_cbc_decrypt

b_wincred_unlock_keyring_internal <- function(keyring, password = NULL) {
  target_lock <- b_wincred_target_lock(keyring)
  if (b_wincred_i_exists(target_lock)) {
    base64_decode(b_wincred_i_get(target_lock))
  } else {
    target_keyring <- b_wincred_target_keyring(keyring)
    keyring_data <- b_wincred_parse_keyring_credential(target_keyring)
    if (is.null(password)) {
      message("keyring ", sQuote(keyring), " is locked, enter password to unlock")
      password <- get_pass()
    }
    aes <- sha256(charToRaw(password), key = keyring_data$Salt)
    verify <- b_wincred_get_encrypted_aes(keyring_data$Verify)
    tryCatch(
      aes_cbc_decrypt(verify, key = aes),
      error = function(e) stop("Invalid password, cannot unlock keyring")
    )
    b_wincred_i_set(target_lock, base64_encode(aes), session = TRUE)
    aes
  }
}

## -----------------------------------------------------------------------

#' Create a Windows Credential Store keyring backend
#'
#' This backend is the default on Windows. It uses the native Windows
#' Credential API, and needs at least Windows XP to run.
#'
#' This backend supports multiple keyrings. Note that multiple keyrings
#' are implemented in the `keyring` R package, using some dummy keyring
#' keys that represent keyrings and their locked/unlocked state.
#'
#' See [backend] for the documentation of the individual methods.
#'
#' @family keyring backends
#' @export
#' @examples
#' \dontrun{
#' ## This only works on Windows
#' kb <- backend_wincred$new()
#' kb$create_keyring("foobar")
#' kb$set_default_keyring("foobar")
#' kb$set_with_value("service", password = "secret")
#' kb$get("service")
#' kb$delete("service")
#' kb$delete_keyring("foobar")
#' }

backend_wincred <- R6Class(
  "backend_wincred",
  inherit = backend_keyrings,
  public = list(
    name = "windows credential store",
    initialize = function(keyring = NULL)
      b_wincred_init(self, private, keyring),

    get = function(service, username = NULL, keyring = NULL)
      b_wincred_get(self, private, service, username, keyring),
    set = function(service, username = NULL, keyring = NULL)
      b_wincred_set(self, private, service, username, keyring),
    set_with_value = function(service, username = NULL, password = NULL,
      keyring = NULL)
      b_wincred_set_with_value(self, private, service, username, password,
                             keyring),
    delete = function(service, username = NULL, keyring = NULL)
      b_wincred_delete(self, private, service, username, keyring),
    list = function(service = NULL, keyring = NULL)
      b_wincred_list(self, private, service, keyring),

    keyring_create = function(keyring)
      b_wincred_keyring_create(self, private, keyring),
    keyring_list = function()
      b_wincred_keyring_list(self, private),
    keyring_delete = function(keyring = NULL)
      b_wincred_keyring_delete(self, private, keyring),
    keyring_lock = function(keyring = NULL)
      b_wincred_keyring_lock(self, private, keyring),
    keyring_unlock = function(keyring = NULL, password = NULL)
      b_wincred_keyring_unlock(self, private, keyring, password),
    keyring_default = function()
      b_wincred_keyring_default(self, private),
    keyring_set_default = function(keyring = NULL)
      b_wincred_keyring_set_default(self, private, keyring)
  ),

  private = list(
    keyring = NULL,
    keyring_create_direct = function(keyring, password)
      b_wincred_keyring_create_direct(self, private, keyring, password)
  )
)

b_wincred_init <- function(self, private, keyring) {
  private$keyring <- keyring
  invisible(self)
}

#' Get a key from a Wincred keyring
#'
#' @param backend Backend object.
#' @param service Service name. Must not be empty.
#' @param username Username. Might be empty.
#'
#' 1. We check if the key is on the default keyring.
#' 2. If yes, we just return it.
#' 3. Otherwise check if the keyring is locked.
#' 4. If locked, then unlock it.
#' 5. Get the AES key from the keyring.
#' 6. Decrypt the key with the AES key.
#'
#' @keywords internal

b_wincred_get <- function(self, private, service, username, keyring) {
  keyring <- keyring %||% private$keyring
  target <- b_wincred_target(keyring, service, username)
  password <- b_wincred_i_get(target)
  if (is.null(keyring)) return(password)

  ## If it is encrypted, we need to decrypt it
  aes <- b_wincred_unlock_keyring_internal(keyring)
  enc <- b_wincred_get_encrypted_aes(password)
  rawToChar(aes_cbc_decrypt(enc, key = aes))
}

b_wincred_set <- function(self, private, service, username, keyring) {
  password <- get_pass()
  b_wincred_set_with_value(self, private, service, username, password,
                           keyring)
  invisible(self)
}

#' Set a key on a Wincred keyring
#'
#' @param service Service name. Must not be empty.
#' @param username Username. Might be empty.
#' @param password The key text to store.
#'
#' 1. Check if we are using the default keyring.
#' 2. If yes, then just store the key and we are done.
#' 3. Otherwise check if keyring exists.
#' 4. If not, error and finish.
#' 5. If yes, check if it is locked.
#' 6. If yes, unlock it.
#' 7. Encrypt the key with the AES key, and store it.
#'
#' @keywords internal

b_wincred_set_with_value <- function(self, private, service,
                                     username, password, keyring) {
  keyring <- keyring %||% private$keyring
  target <- b_wincred_target(keyring, service, username)
  if (is.null(keyring)) {
    b_wincred_i_set(target, password, username = username)
    return(invisible(self))
  }

  ## Not the default keyring, we need to encrypt it
  target_keyring <- b_wincred_target_keyring(keyring)
  aes <- b_wincred_unlock_keyring_internal(keyring)
  enc <- aes_cbc_encrypt(charToRaw(password), key = aes)
  b_wincred_i_set(target, password = base64_encode(c(attr(enc, "iv"), enc)),
                        username = username)
  invisible(self)
}

b_wincred_delete <- function(self, private, service, username, keyring) {
  keyring <- keyring %||% private$keyring
  target <- b_wincred_target(keyring, service, username)
  b_wincred_i_delete(target)
  invisible(self)
}

b_wincred_list <- function(self, private, service, keyring) {
  keyring <- keyring %||% private$keyring

  filter <- if (is.null(service)) {
    paste0(keyring, ":*")
  } else {
    paste0(keyring, ":", service, ":*")
  }

  list <- b_wincred_i_enumerate(filter)

  ## Filter out the credentials that belong to the keyring or its lock
  list <- grep("(::|::unlocked)$", list, value = TRUE, invert = TRUE)

  parts <- b_wincred_i_parse_target(list)
  data.frame(
    service = parts$service,
    username = parts$username,
    stringsAsFactors = FALSE
  )
}

b_wincred_keyring_create <- function(self, private, keyring) {
  password <- get_pass()
  private$keyring_create_direct(keyring, password)
  invisible(self)
}

## 1. Check that the keyring does not exist, error if it does
## 2. Create salt.
## 3. SHA256 hash the password, with the salt, to get the AES key.
## 4. Generate 15 random bytes, encrypt it with the AES key, base64 encode it.
## 5. Write metadata to the keyring credential
## 6. Unlock the keyring immediately, create a keyring unlock credential

#' @importFrom openssl base64_encode rand_bytes aes_cbc_encrypt

b_wincred_keyring_create_direct <- function(self, private, keyring,
                                            password) {
  target_keyring <- b_wincred_target_keyring(keyring)
  if (b_wincred_i_exists(target_keyring)) {
    stop("keyring ", sQuote(keyring), " already exists")
  }
  salt <- base64_encode(rand_bytes(32))
  aes <- sha256(charToRaw(password), key = salt)
  verify <- aes_cbc_encrypt(rand_bytes(15), key = aes)
  verify <- base64_encode(c(attr(verify, "iv"), verify))
  dcf <- list(
    Version = b_wincred_protocol_version,
    Verify = verify,
    Salt = salt
  )
  b_wincred_write_keyring_credential(target_keyring, dcf)
  b_wincred_unlock_keyring_internal(keyring, password)
  invisible(self)
}

b_wincred_keyring_list <- function(self, private) {
  list <- b_wincred_i_enumerate("*")
  parts <- b_wincred_i_parse_target(list)

  ## if keyring:: does not exist, then keyring is not a real keyring, assign it
  ## to the default
  default <- ! paste0(parts$keyring, "::") %in% list
  if (any(default)) {
    parts$username[default] <-
      paste0(parts$service[default], ":", parts$username[default])
    parts$service[default] <- parts$keyring[default]
    parts$keyring[default] <- ""
  }

  res <- data.frame(
    stringsAsFactors = FALSE,
    keyring = unname(unique(parts$keyring)),
    num_secrets = as.integer(unlist(tapply(parts$keyring, parts$keyring,
      length, simplify = FALSE))),
    locked = vapply(unique(parts$keyring), FUN.VALUE = TRUE, USE.NAMES = FALSE,
      function(x) {
        ! any(parts$username[parts$keyring == x] == "unlocked")
      }
    )
  )

  ## Subtract keyring::unlocked and also keyring:: for the non-default keyring
  res$num_secrets <- res$num_secrets - (! res$locked) - (res$keyring != "")

  ## The default keyring cannot be locked
  if ("" %in% res$keyring) res$locked[res$keyring == ""] <- FALSE

  res
}

b_wincred_keyring_delete <- function(self, private, keyring) {
  keyring <- keyring %||% private$keyring

  if (is.null(keyring)) stop("Cannot delete the default keyring")
  ## TODO: confirmation
  target_keyring <- b_wincred_target_keyring(keyring)
  b_wincred_i_delete(target_keyring)
  target_lock <- b_wincred_target_lock(keyring)
  try(b_wincred_i_delete(target_lock), silent = TRUE)
  invisible()
}

b_wincred_keyring_lock <- function(self, private, keyring) {
  keyring <- keyring %||% private$keyring
  if (is.null(keyring)) {
    warning("Cannot lock the default windows credential store keyring")
  } else {
    target_lock <- b_wincred_target_lock(keyring)
    try(b_wincred_i_delete(target_lock), silent = TRUE)
    invisible()
  }
}

b_wincred_keyring_unlock <- function(self, private, keyring,
                                     password = NULL) {
  keyring <- keyring %||% private$keyring
  if (is.null(password)) password <- get_pass()
  if (!is.null(keyring)) {
    b_wincred_unlock_keyring_internal(keyring, password)
  }
  invisible()
}

b_wincred_keyring_default <- function(self, private) {
  private$keyring
}

b_wincred_keyring_set_default <- function(self, private, keyring) {
  private$keyring <- keyring
  invisible(self)
}
