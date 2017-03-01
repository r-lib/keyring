
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

backend_wincred_protocol_version <- "1.0.0"

## This is a low level API

backend_wincred_i_get <- function(target) {
  .Call("keyring_wincred_get", target, PACKAGE = "keyring")
}

backend_wincred_i_set <- function(target, password, username = NULL,
		                  session = FALSE) {
  .Call("keyring_wincred_set", target, password, username, session,
        PACKAGE = "keyring")
}

backend_wincred_i_delete <- function(target) {
  .Call("keyring_wincred_delete", target, PACKAGE = "keyring")
}

backend_wincred_i_exists <- function(target) {
  .Call("keyring_wincred_exists", target, PACKAGE = "keyring")
}

backend_wincred_i_enumerate <- function(filter) {
  .Call("keyring_wincred_enumerate", filter, PACKAGE = "keyring")
}

#' Create a Windows Credential Store keyring backend
#'
#' This backend is the default on Windows. It uses the native Windows
#' Credential API, and needs at least Windows XP to run.
#'
#' This backend supports multiple keyrings. Note that multiple keyrings
#' are implemented in the `keyring` R package, using some dummy keyring
#' keys that represent keyrings and their locked/unlocked state.
#'
#' @param keyring Name of the keyring to use. `NULL` specifies the
#'   default keyring.
#' @return A backend object that can be used in `keyring` functions.
#'
#' @family keyring backends
#' @export

backend_wincred <- function(keyring = NULL) {
  assert_that(is_string_or_null(keyring))
  make_backend(
    name = "secret service",
    keyring = keyring,
    get = backend_wincred_get,
    set = backend_wincred_set,
    set_with_value = backend_wincred_set_with_value,
    delete = backend_wincred_delete,
    list = backend_wincred_list,
    keyring_create = backend_wincred_create_keyring,
    keyring_list = backend_wincred_list_keyring,
    keyring_delete = backend_wincred_delete_keyring,
    keyring_lock = backend_wincred_lock_keyring,
    keyring_unlock = backend_wincred_unlock_keyring
  )
}

#' @importFrom utils URLencode

backend_wincred_i_escape <- function(x) {
  URLencode(x, reserved = TRUE, repeated = TRUE)
}

#' @importFrom utils URLdecode

backend_wincred_i_unescape <- function(x) {
  URLdecode(x)
}

backend_wincred_target <- function(keyring, service, username) {
  keyring <- if (is.null(keyring)) "" else backend_wincred_i_escape(keyring)
  service <- backend_wincred_i_escape(service)
  username <- if (is.null(username)) "" else backend_wincred_i_escape(username)
  paste0(keyring, ":", service, ":", username)
}

## For the username we need a workaround, because
## strsplit("foo::")[[1]] gives c("foo", ""), i.e. the third empty element
## is cut off.

backend_wincred_i_parse_target <- function(target) {
  parts <- lapply(strsplit(target, ":"), lapply, backend_wincred_i_unescape)
  res <- data.frame(
    stringsAsFactors = FALSE,
    keyring = vapply(parts, "[[", "", 1),
    service = vapply(parts, "[[", "", 2),
    username = vapply(parts, function(x) x[3][[1]] %||% "", "")
  )
}

backend_wincred_target_keyring <- function(keyring) {
  backend_wincred_target(keyring, "", "")
}

backend_wincred_target_lock <- function(keyring) {
  backend_wincred_target(keyring, "", "unlocked")
}

backend_wincred_parse_keyring_credential <- function(target) {
  value <- backend_wincred_i_get(target)
  con <- textConnection(value)
  on.exit(close(con), add = TRUE)
  as.list(read.dcf(con)[1,])
}

backend_wincred_write_keyring_credential <- function(target, data) {
  con <- textConnection(NULL, open = "w")
  mat <- matrix(unlist(data), nrow = 1)
  colnames(mat) <- names(data)
  write.dcf(mat, con)
  value <- paste0(paste(textConnectionValue(con), collapse = "\n"), "\n")
  close(con)
  backend_wincred_i_set(target, password = value)
}

#' @importFrom openssl base64_decode
#' @importFrom utils head tail

backend_wincred_get_encrypted_aes <- function(str) {
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

backend_wincred_unlock_keyring_internal <- function(keyring, password = NULL) {
  target_lock <- backend_wincred_target_lock(keyring)
  if (backend_wincred_i_exists(target_lock)) {
    base64_decode(backend_wincred_i_get(target_lock))
  } else {
    target_keyring <- backend_wincred_target_keyring(keyring)
    keyring_data <- backend_wincred_parse_keyring_credential(target_keyring)
    if (is.null(password)) {
      message("keyring ", sQuote(keyring), " is locked, enter password to unlock")
      password <- get_pass()
    }
    aes <- sha256(charToRaw(password), key = keyring_data$Salt)
    verify <- backend_wincred_get_encrypted_aes(keyring_data$Verify)
    tryCatch(
      aes_cbc_decrypt(verify, key = aes),
      error = function(e) stop("Invalid password, cannot unlock keyring")
    )
    backend_wincred_i_set(target_lock, base64_encode(aes), session = TRUE)
    aes
  }
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

backend_wincred_get <- function(backend, service, username) {
  target <- backend_wincred_target(backend$keyring, service, username)
  password <- backend_wincred_i_get(target)
  if (is.null(backend$keyring)) return(password)

  ## If it is encrypted, we need to decrypt it
  aes <- backend_wincred_unlock_keyring_internal(backend$keyring)
  enc <- backend_wincred_get_encrypted_aes(password)
  rawToChar(aes_cbc_decrypt(enc, key = aes))
}

backend_wincred_set <- function(backend, service, username) {
  pw <- get_pass()
  backend_wincred_set_with_value(backend, service, username, pw)
}

#' Set a key on a Wincred keyring
#'
#' @param backend The backend object.
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

backend_wincred_set_with_value <- function(backend, service,
                                           username, password) {
  target <- backend_wincred_target(backend$keyring, service, username)
  if (is.null(backend$keyring)) {
    backend_wincred_i_set(target, password, username = username)
    return(invisible())
  }

  ## Not the default keyring, we need to encrypt it
  target_keyring <- backend_wincred_target_keyring(backend$keyring)
  aes <- backend_wincred_unlock_keyring_internal(backend$keyring)
  enc <- aes_cbc_encrypt(charToRaw(password), key = aes)
  backend_wincred_i_set(target, password = base64_encode(c(attr(enc, "iv"), enc)),
                        username = username)
  invisible()
}

backend_wincred_delete <- function(backend, service, username) {
  target <- backend_wincred_target(backend$keyring, service, username)
  backend_wincred_i_delete(target)
  invisible()
}

backend_wincred_list <- function(backend, service) {

  filter <- if (is.null(service)) {
    paste0(backend$keyring, ":*")
  } else {
    paste0(backend$keyring, ":", service, ":*")
  }

  list <- backend_wincred_i_enumerate(filter)

  ## Filter out the credentials that belong to the keyring or its lock
  list <- grep("(::|::unlocked)$", list, value = TRUE, invert = TRUE)

  parts <- backend_wincred_i_parse_target(list)
  data.frame(
    service = parts$service,
    username = parts$username,
    stringsAsFactors = FALSE
  )
}

backend_wincred_create_keyring <- function(backend) {
  pw <- get_pass()
  backend_wincred_create_keyring_direct(backend$keyring, pw)
}

## 1. Check that the keyring does not exist, error if it does
## 2. Create salt.
## 3. SHA256 hash the password, with the salt, to get the AES key.
## 4. Generate 15 random bytes, encrypt it with the AES key, base64 encode it.
## 5. Write metadata to the keyring credential
## 6. Unlock the keyring immediately, create a keyring unlock credential

#' @importFrom openssl base64_encode rand_bytes aes_cbc_encrypt

backend_wincred_create_keyring_direct <- function(keyring, pw) {
  target_keyring <- backend_wincred_target_keyring(keyring)
  if (backend_wincred_i_exists(target_keyring)) {
    stop("keyring ", sQuote(keyring), " already exists")
  }
  salt <- base64_encode(rand_bytes(32))
  aes <- sha256(charToRaw(pw), key = salt)
  verify <- aes_cbc_encrypt(rand_bytes(15), key = aes)
  verify <- base64_encode(c(attr(verify, "iv"), verify))
  dcf <- list(
    Version = backend_wincred_protocol_version,
    Verify = verify,
    Salt = salt
  )
  backend_wincred_write_keyring_credential(target_keyring, dcf)
  backend_wincred_unlock_keyring_internal(keyring, pw)
  invisible()
}

backend_wincred_list_keyring <- function(backend) {
  list <- backend_wincred_i_enumerate("*")
  parts <- backend_wincred_i_parse_target(list)

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

backend_wincred_delete_keyring <- function(backend) {
  if (is.null(backend$keyring)) stop("Cannot delete the default keyring")
  ## TODO: confirmation
  target_keyring <- backend_wincred_target_keyring(backend$keyring)
  backend_wincred_i_delete(target_keyring)
  target_lock <- backend_wincred_target_lock(backend$keyring)
  try(backend_wincred_i_delete(target_lock), silent = TRUE)
  invisible()
}

backend_wincred_lock_keyring <- function(backend) {
  if (is.null(backend$keyring)) {
    warning("Cannot lock the default windows credential store keyring")
  } else {
    target_lock <- backend_wincred_target_lock(backend$keyring)
    try(backend_wincred_i_delete(target_lock), silent = TRUE)
    invisible()
  }
}

backend_wincred_unlock_keyring <- function(backend, password = NULL) {
  if (is.null(password)) password <- get_pass()
  if (!is.null(backend$keyring)) {
    backend_wincred_unlock_keyring_internal(backend$keyring, password)
  }
  invisible()
}
