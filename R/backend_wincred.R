
## The windows credential store does not support multiple keyrings,
## so we emulate them.
##
## For every (non-default) keyring, we create a credential, with target name
## "keyring::". This credential contains an RSA keypair, in PEM
## format. The private key PEM also has a password, this is the
## keyring password. This is how it looks:
##
## -----BEGIN PUBLIC KEY-----
## MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA+ditW7cKwYn/lBr7PjVH
## ...
## -----END PUBLIC KEY-----
## -----BEGIN ENCRYPTED PRIVATE KEY-----
## MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIlHZxySV0zOACAggA
## ...
## -----END ENCRYPTED PRIVATE KEY-----
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
    delete_keyring = backend_wincred_delete_keyring
  )
}

backend_wincred_target <- function(keyring, service, username) {
  paste0(":", service, ":", username)
}

backend_wincred_target_keyring <- function(keyring) {
  paste0(keyring, "::")
}

backend_wincred_target_lock <- function(keyring) {
  paste0(keyring, "::unlocked")
}

## 1. Try to get the unlock credential
## 2. If it exists, return the unencrypted key
## 3. If not, then get the credential of the keyring
## 4. Ask for its password
## 5. Decrypt the key with the password
## 6. Create a SESSION credential, with the decrypted key
## 7. Return the decrypted key

#' @importFrom openssl read_key

backend_wincred_unlock_keyring <- function(keyring) {
  target_lock <- backend_wincred_target_lock(keyring)
  if (backend_wincred_i_exists(target_lock)) {
    backend_wincred_i_get(target_lock)
  } else {
    target_keyring <- backend_wincred_target_keyring(keyring)
    en_key <- backend_wincred_i_get(target_keyring)
    message("keyring ", sQuote(keyring), " is locked, enter password to unlock")
    pw <- get_pass()
    key <- read_key(en_key, password = pw)
    backend_wincred_i_set(target_lock, key, session = TRUE)
    key
  }
}

backend_wincred_get <- function(backend, service, username) {
  target <- backend_wincred_target(backend$keyring, service, username)
  password <- backend_wincred_i_get(target)
  if (is.null(backend$keyring)) return(password)

  ## If it is encrypted, we need to decrypt it
  key <- backend_wincred_unlock_keyrinf(backend$keyring)
  rsa_decrypt(password, key = key)
}

backend_wincred_set <- function(backend, service, username) {
  ps <- get_pass()
  backend_wincred_set_with_value(backend, service, username, pw)
}

#' @importFrom openssl rsa_encrypt

backend_wincred_set_with_value <- function(backend, service,
                                           username, password) {
  target <- backend_wincred_target(backend$keyring, service, username)
  if (is.null(backend$keyring)) {
    backend_wincred_i_set(target, password, username = username)
    return(invisible())
  }

  ## Not the default keyring, we need to encrypt it
  target_keyring <- backend_wincred_target_keyring(backend$keyring)
  key <- backend_wincred_i_get(target_keyring)
  cipher <- rsa_encrypt(password, key = key)
  backend_wincred_i_set(target, password = cipher, username = username)
  invisible()
}

backend_wincred_delete <- function(backend, service, username) {
  target <- backend_wincred_target(backend$keyring, service, username)
  backend_wincred_i_delete(target)
  invisible()
}

backend_wincred_target_service <- function(x) {
  pc <- strsplit(x, ":")
  vapply(pc, FUN.VALUE = "", function(xx) {
    paste(xx[2:(length(xx)-1)], collapse = "")
  })
}

backend_wincred_target_username <- function(x) {
  pc <- strsplit(x, ":")
  vapply(pc, tail, 1, FUN.VALUE = "")
}

backend_wincred_list <- function(backend, service) {

  filter <- if (is.null(service)) {
    paste0(backend$keyring, ":*")
  } else {
    paste0(backend$keyring, ":", service, ":*")
  }

  list <- backend_wincred_i_enumerate(filter)
  data.frame(
    service = backend_wincred_target_service(list),
    username = backend_wincred_target_username(list),
    stringsAsFactors = FALSE
  )
}

backend_wincred_create_keyring <- function(backend) {
  pw <- get_pass()
  backend_wincred_create_keyring_direct(backend$keyring, pw)
}

backend_wincred_create_keyring_direct <- function(keyring, pw = NULL) {
  # TODO
  invisible()
}

backend_wincred_list_keyring <- function(backend) {
  # TODO
}

backend_wincred_delete_keyring <- function(backend) {
  # TODO
}
