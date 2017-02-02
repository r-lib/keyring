
#ifdef __APPLE__

#include <Security/Security.h>

#include <R.h>
#include <Rinternals.h>

#include <string.h>

/* TODO: set encoding to UTF-8? */

SEXP keyring_macos_get(SEXP service, SEXP username) {

  const char* cservice = CHAR(STRING_ELT(service, 0));
  const char* cusername = CHAR(STRING_ELT(username, 0));

  void *data;
  UInt32 length;
  SEXP result;

  OSStatus status = SecKeychainFindGenericPassword(
    /* keychainOrArray = */ NULL,
    (UInt32) strlen(cservice), cservice,
    (UInt32) strlen(cusername), cusername,
    &length, &data,
    /* itemRef = */ NULL);

  if (status != errSecSuccess) error("Cannot find macOS Keychain item");

  result = PROTECT(ScalarString(mkCharLen((const char*) data, length)));
  SecKeychainItemFreeContent(NULL, data);

  UNPROTECT(1);
  return result;
}

/* TODO: recode in UTF8 */

SEXP keyring_macos_set(SEXP service, SEXP username, SEXP password) {

  const char* cservice = CHAR(STRING_ELT(service, 0));
  const char* cusername = CHAR(STRING_ELT(username, 0));
  const char* cpassword = CHAR(STRING_ELT(password, 0));

  OSStatus status = SecKeychainAddGenericPassword(
    /* keychain =  */ NULL,
    (UInt32) strlen(cservice), cservice,
    (UInt32) strlen(cusername), cusername,
    (UInt32) strlen(cpassword), cpassword,
    /* itemRef = */ NULL);

  if (status != errSecSuccess) error("Cannot set macOS Keychain item");

  return R_NilValue;
}

SEXP keyring_macos_delete(SEXP service, SEXP username) {

  const char* cservice = CHAR(STRING_ELT(service, 0));
  const char* cusername = CHAR(STRING_ELT(username, 0));

  SecKeychainItemRef item;

  OSStatus status = SecKeychainFindGenericPassword(
    /* keychainOrArray = */ NULL,
    (UInt32) strlen(cservice), cservice,
    (UInt32) strlen(cusername), cusername,
    /* *passwordLength = */ NULL, /* *passwordData = */ NULL,
    &item);

  if (status != errSecSuccess) error("Cannot find macOS Keychain item");

  status = SecKeychainItemDelete(item);
  if (status != errSecSuccess) error("Cannot delete macOS Keychain item");

  CFRelease(item);

  return R_NilValue;
}

SEXP keyring_macos_list(SEXP service) {
  // TODO
  return R_NilValue;
}

#endif // __APPLE__
