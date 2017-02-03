
#ifdef __APPLE__

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <R.h>
#include <Rinternals.h>

#include <string.h>

void keyring_macos_error(const char *func, OSStatus status) {
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
}

void keyring_macos_handle_status(const char *func, OSStatus status) {
  if (status != errSecSuccess) keyring_macos_error(func, status);
}

/* TODO: set encoding to UTF-8? */

SEXP keyring_macos_get(SEXP keyring, SEXP service, SEXP username) {

  const char* empty = "";
  const char* cservice = CHAR(STRING_ELT(service, 0));
  const char* cusername =
    isNull(username) ? empty :CHAR(STRING_ELT(username, 0));

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

SEXP keyring_macos_set(SEXP keyring, SEXP service, SEXP username,
		       SEXP password) {

  const char* empty = "";
  const char* cservice = CHAR(STRING_ELT(service, 0));
  const char* cusername =
    isNull(username) ? empty : CHAR(STRING_ELT(username, 0));
  const char* cpassword = CHAR(STRING_ELT(password, 0));
  SecKeychainItemRef item;

  /* Try to find it, and it is exists, update it */

  OSStatus status = SecKeychainFindGenericPassword(
    /* keychainOrArray = */ NULL,
    (UInt32) strlen(cservice), cservice,
    (UInt32) strlen(cusername), cusername,
    /* passwordLength = */ NULL, /* passwordData = */ NULL,
    &item);

  if (status == errSecItemNotFound) {
    status = SecKeychainAddGenericPassword(
      /* keychain =  */ NULL,
      (UInt32) strlen(cservice), cservice,
      (UInt32) strlen(cusername), cusername,
      (UInt32) strlen(cpassword), cpassword,
      /* itemRef = */ NULL);

  } else {
    status = SecKeychainItemModifyAttributesAndData(
      item,
      /* attrList= */ NULL,
      (UInt32) strlen(cpassword), cpassword);
    CFRelease(item);
  }

  if (status != errSecSuccess) keyring_macos_error("set", status);

  return R_NilValue;
}

SEXP keyring_macos_delete(SEXP keyring, SEXP service, SEXP username) {

  const char* empty = "";
  const char* cservice = CHAR(STRING_ELT(service, 0));
  const char* cusername =
    isNull(username) ? empty : CHAR(STRING_ELT(username, 0));

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

static void keyring_macos_list_item(SecKeychainItemRef item, SEXP result,
				    int idx) {
  SecItemClass class;
  SecKeychainAttribute attrs[] = {
    { kSecServiceItemAttr },
    { kSecAccountItemAttr }
  };
  SecKeychainAttributeList attrList = { 2, attrs };

  if (SecKeychainItemGetTypeID() != CFGetTypeID(item)) {
    SET_STRING_ELT(VECTOR_ELT(result, 0), idx, mkChar(""));
    SET_STRING_ELT(VECTOR_ELT(result, 1), idx, mkChar(""));
    return;
  }

  OSStatus status = SecKeychainItemCopyContent(item, &class, &attrList,
					       /* length = */ NULL,
					       /* outData = */ NULL);
  keyring_macos_handle_status("list", status);
  SET_STRING_ELT(VECTOR_ELT(result, 0), idx,
		 mkCharLen(attrs[0].data, attrs[0].length));
  SET_STRING_ELT(VECTOR_ELT(result, 1), idx,
		 mkCharLen(attrs[1].data, attrs[1].length));
  SecKeychainItemFreeContent(&attrList, NULL);
}

SEXP keyring_macos_list(SEXP keyring, SEXP service) {

  CFStringRef cfservice = NULL;

  CFMutableDictionaryRef query = CFDictionaryCreateMutable(
    kCFAllocatorDefault, 0,
    &kCFTypeDictionaryKeyCallBacks,
    &kCFTypeDictionaryValueCallBacks);

  CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);
  CFDictionarySetValue(query, kSecReturnData, kCFBooleanFalse);
  CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
  CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);

  if (!isNull(service)) {
    const char *cservice = CHAR(STRING_ELT(service, 0));
    cfservice = CFStringCreateWithBytes(
      /* alloc = */ NULL,
      (const UInt8*) cservice, strlen(cservice),
      kCFStringEncodingUTF8,
      /* isExternalRepresentation = */ 0);
      CFDictionarySetValue(query, kSecAttrService, cfservice);
  }

  CFArrayRef resArray = NULL;
  OSStatus status = SecItemCopyMatching(query, (CFTypeRef*) &resArray);
  CFRelease(query);
  if (cfservice != NULL) CFRelease(cfservice);

  if (status != errSecSuccess) {
    if (resArray != NULL) CFRelease(resArray);
    if (status != errSecSuccess) keyring_macos_error("list", status);
    return R_NilValue;

  } else {
    CFIndex i, num = CFArrayGetCount(resArray);
    SEXP result;
    PROTECT(result = allocVector(VECSXP, 2));
    SET_VECTOR_ELT(result, 0, allocVector(STRSXP, num));
    SET_VECTOR_ELT(result, 1, allocVector(STRSXP, num));
    for (i = 0; i < num; i++) {
      SecKeychainItemRef item =
	(SecKeychainItemRef) CFArrayGetValueAtIndex(resArray, i);
      keyring_macos_list_item(item, result, (int) i);
    }

    CFRelease(resArray);
    UNPROTECT(1);
    return result;
  }
}

#endif // __APPLE__
