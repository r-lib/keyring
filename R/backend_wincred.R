
## The windows credential store does not support multiple keyrings,
## so we emulate them.
##
## For every (non-default) keyring, we create a credential, with target name
## "keyring::". This credential contains an RSA keypair, in PEM
## format. The private key PEM also has a password, this is the
## keyring password. This is how it looks:
##
## -----BEGIN ENCRYPTED PRIVATE KEY-----
## MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIlHZxySV0zOACAggA
## ...
## -----END ENCRYPTED PRIVATE KEY-----
##
## -----BEGIN PUBLIC KEY-----
## MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA+ditW7cKwYn/lBr7PjVH
## ...
## -----END PUBLIC KEY-----
##
## When a keyring is unlocked, we store another credential, with target
## name "keyring::unlocked". This is a session credential, i.e. it is
## only for a single login session. This credential has the decrypted
## private key:
## -----BEGIN PRIVATE KEY-----
## MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD52K1btwrBif+U
## ...
## -----END PRIVATE KEY-----
##
## The credentials of the keyring itself have target names as
## "keyring:service:username", where the username may be empty.
## If keyring is empty, then the credential is considered to be
## on the default keyring, and it is not encrypted. Credentials on
## other keyrings are encrypted using the public key of the keyring.
##
## When we 'set' a key, we need to:
## 1. Check if the key is on the default keyring.
## 2. If 1. is TRUE, then just set the key, using target name
##    ":service:username" (username might be empty, servicename not),
##    and fininsh.
## 3. Check if the keyring exists.
## 4. If 3. is FALSE, then error and finished.
## 5. Get the public key of the keyring.
## 6. Encrypt the key with the public key, and store the encrypted
##    key using target name "keyring:service:username" (again, username
##    might be empty, service name not).
##
## Note that, since the public key is always available, the stored
## key can be overwritten without unlocking the keyring.
##
## When we 'get' a key, we need to:
## 1. Check if the key is on the default keyring.
## 2. If 1. is TRUE, then we just get the key, using target name
##    ":service:username".
## 3. Check if the keyring is locked.
## 4. If 3. is TRUE, then prompt the user and unlock the keyring.
## 5. Get the private key from the unlocked keyring.
## 6. Get the key and use the private key to decrypt it.
##
## The C functions for the wincred backend do not know about multiple
## keyrings at all, we just use them to get/set/delete/list "regular"
## credentials in the credential store.

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
    create_keyring = backend_wincred_create_keyring,
    list_keyring = backend_wincred_list_keyring,
    delete_keyring = backend_wincred_delete_keyring,
    lock_keyring = backend_wincred_lock_keyring,
    unlock_keyring = backend_wincred_unlock_keyring
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
  list(
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

extract_privkey <- function(txt) {
  paste0(strsplit(txt, "\n\n")[[1]][1], "\n")
}

extract_pubkey <- function(txt) {
  strsplit(txt, "\n\n")[[1]][2]
}

## 1. Try to get the unlock credential
## 2. If it exists, return the unencrypted key
## 3. If not, then get the credential of the keyring
## 4. Ask for its password
## 5. Decrypt the key with the password
## 6. Create a SESSION credential, with the decrypted key
## 7. Return the decrypted key

#' @importFrom openssl read_key

backend_wincred_unlock_keyring_internal <- function(keyring, password = NULL) {
  target_lock <- backend_wincred_target_lock(keyring)
  if (backend_wincred_i_exists(target_lock)) {
    backend_wincred_i_get(target_lock)
  } else {
    target_keyring <- backend_wincred_target_keyring(keyring)
    en_key <- extract_privkey(backend_wincred_i_get(target_keyring))
    if (is.null(password)) {
      message("keyring ", sQuote(keyring), " is locked, enter password to unlock")
      password <- get_pass()
    }
    key <- write_pem(read_key(en_key, password = password))
    backend_wincred_i_set(target_lock, key, session = TRUE)
    key
  }
}

#' @importFrom openssl base64_decode

backend_wincred_get <- function(backend, service, username) {
  target <- backend_wincred_target(backend$keyring, service, username)
  password <- backend_wincred_i_get(target)
  if (is.null(backend$keyring)) return(password)

  ## If it is encrypted, we need to decrypt it
  key <- backend_wincred_unlock_keyring_internal(backend$keyring)
  rawToChar(rsa_decrypt(base64_decode(password), key = key))
}

backend_wincred_set <- function(backend, service, username) {
  ps <- get_pass()
  backend_wincred_set_with_value(backend, service, username, pw)
}

#' @importFrom openssl rsa_encrypt base64_encode

backend_wincred_set_with_value <- function(backend, service,
                                           username, password) {
  target <- backend_wincred_target(backend$keyring, service, username)
  if (is.null(backend$keyring)) {
    backend_wincred_i_set(target, password, username = username)
    return(invisible())
  }

  ## Not the default keyring, we need to encrypt it
  target_keyring <- backend_wincred_target_keyring(backend$keyring)
  pubkey <- extract_pubkey(backend_wincred_i_get(target_keyring))
  cipher <- rsa_encrypt(charToRaw(password), pubkey = pubkey)
  backend_wincred_i_set(target, password = base64_encode(cipher),
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
## 2. Create an RSA keypair
## 3. Write it to a keyring credential
## 4. Unlock the keyring immediately, create a keyring lock credential

#' @importFrom openssl rsa_keygen write_pem

backend_wincred_create_keyring_direct <- function(keyring, pw) {
  target_keyring <- backend_wincred_target_keyring(keyring)
  if (backend_wincred_i_exists(target_keyring)) {
    error("keyring ", sQuote(keyring), " already exists")
  }
  key <- rsa_keygen()
  pem <- paste(
    write_pem(key, password = pw),
    sep = "\n",
    write_pem(key$pubkey)
  )
  backend_wincred_i_set(target_keyring, password = pem)
  plainpem <- write_pem(key)
  target_lock <- backend_wincred_target_lock(keyring)
  backend_wincred_i_set(target_lock, password = plainpem, session = TRUE)
  invisible()
}

backend_wincred_list_keyring <- function(backend) {
  list <- backend_wincred_i_enumerate("*")
  list <- grep("::", list, value = TRUE)
  keyring <- grep("::$", list, value = TRUE)
  num <- vapply(keyring, FUN.VALUE = 1L, function(x) {
    mykeys <- list[substr(list, 1, nchar(x)) == x]
    mykeys <- grep("(::|::unlocked)$", mykeys, value = TRUE, invert = TRUE)
    length(mykeys)
  })
  locked <- if (!length(keyring)) {
    logical()
  } else {
    ! paste0(keyring, "unlocked") %in% list
  }
  data.frame(
    keyring = backend_wincred_i_parse_target(keyring)$keyring,
    num_secrets = unname(num),
    locked = unname(locked),
    stringsAsFactors = FALSE
  )
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
