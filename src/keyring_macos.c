
#ifdef __APPLE__

#include <Security/Security.h>

#include <R.h>
#include <Rinternals.h>

#include <string.h>

SEXP keyring_macos_error(const char *func, OSStatus status) {
  CFStringRef str = SecCopyErrorMessageString(status, NULL);
  CFIndex length = CFStringGetLength(str);
  CFIndex maxSize =
    CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
  char *buffer = R_alloc(1, maxSize);

  if (CFStringGetCString(str, buffer, maxSize, kCFStringEncodingUTF8)) {
    error("macOS Keychain error in '%s': %s", func, buffer);

  } else {
    error("macOS Keychain error in '%s': %s", func, "unknown error");
  }

  return R_NilValue;
}

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

  if (status != errSecSuccess) keyring_macos_error("get", status);

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

  if (status != errSecSuccess) keyring_macos_error("set", status);

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

  if (status != errSecSuccess) keyring_macos_error("delete", status);

  status = SecKeychainItemDelete(item);
  if (status != errSecSuccess) keyring_macos_error("delete", status);

  CFRelease(item);

  return R_NilValue;
}

SEXP keyring_macos_list(SEXP service) {
  // TODO
  return R_NilValue;
}

#endif // __APPLE__
