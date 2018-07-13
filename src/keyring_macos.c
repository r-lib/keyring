
/* Avoid warning about empty compilation unit. */
void keyring_macos_dummy() { }

#ifdef __APPLE__

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <R.h>
#include <R_ext/Rdynload.h>
#include <Rinternals.h>

#include <sys/param.h>
#include <string.h>

void keyring_macos_error(const char *func, OSStatus status) {
  CFStringRef str = SecCopyErrorMessageString(status, NULL);
  CFIndex length = CFStringGetLength(str);
  CFIndex maxSize =
    CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
  char *buffer = R_alloc(maxSize, 1);

  if (CFStringGetCString(str, buffer, maxSize, kCFStringEncodingUTF8)) {
    error("keyring error (macOS Keychain), %s: %s", func, buffer);

  } else {
    error("keyring error (macOS Keychain), %s", func);
  }
}

void keyring_macos_handle_status(const char *func, OSStatus status) {
  if (status != errSecSuccess) keyring_macos_error(func, status);
}

SecKeychainRef keyring_macos_open_keychain(const char *pathName) {
  SecKeychainRef keychain;
  OSStatus status = SecKeychainOpen(pathName, &keychain);
  keyring_macos_handle_status("cannot open keychain", status);

  /* We need to query the status, because SecKeychainOpen succeeds,
     even if the keychain file does not exists. (!) */
  SecKeychainStatus keychainStatus = 0;
  status = SecKeychainGetStatus(keychain, &keychainStatus);
  keyring_macos_handle_status("cannot open keychain", status);

  return keychain;
}

SEXP keyring_macos_get(SEXP keyring, SEXP service, SEXP username) {

  const char* empty = "";
  const char* cservice = CHAR(STRING_ELT(service, 0));
  const char* cusername =
    isNull(username) ? empty :CHAR(STRING_ELT(username, 0));

  void *data;
  UInt32 length;
  SEXP result;

  SecKeychainRef keychain =
    isNull(keyring) ? NULL :
    keyring_macos_open_keychain(CHAR(STRING_ELT(keyring, 0)));

  OSStatus status = SecKeychainFindGenericPassword(
    keychain,
    (UInt32) strlen(cservice), cservice,
    (UInt32) strlen(cusername), cusername,
    &length, &data,
    /* itemRef = */ NULL);

  if (keychain != NULL) CFRelease(keychain);

  keyring_macos_handle_status("cannot get password", status);

  result = PROTECT(allocVector(RAWSXP, length));
  memcpy(RAW(result), data, length);
  SecKeychainItemFreeContent(NULL, data);

  UNPROTECT(1);
  return result;
}

SEXP keyring_macos_set(SEXP keyring, SEXP service, SEXP username,
		       SEXP password) {

  const char* empty = "";
  const char* cservice = CHAR(STRING_ELT(service, 0));
  const char* cusername =
    isNull(username) ? empty : CHAR(STRING_ELT(username, 0));
  SecKeychainItemRef item;

  SecKeychainRef keychain =
    isNull(keyring) ? NULL :
    keyring_macos_open_keychain(CHAR(STRING_ELT(keyring, 0)));

  /* Try to find it, and it is exists, update it */

  OSStatus status = SecKeychainFindGenericPassword(
    keychain,
    (UInt32) strlen(cservice), cservice,
    (UInt32) strlen(cusername), cusername,
    /* passwordLength = */ NULL, /* passwordData = */ NULL,
    &item);

  if (status == errSecItemNotFound) {
    status = SecKeychainAddGenericPassword(
      keychain,
      (UInt32) strlen(cservice), cservice,
      (UInt32) strlen(cusername), cusername,
      (UInt32) LENGTH(password), RAW(password),
      /* itemRef = */ NULL);

  } else {
    status = SecKeychainItemModifyAttributesAndData(
      item,
      /* attrList= */ NULL,
      (UInt32) LENGTH(password), RAW(password));
    CFRelease(item);
  }

  if (keychain != NULL) CFRelease(keychain);

  keyring_macos_handle_status("cannot set password", status);

  return R_NilValue;
}

SEXP keyring_macos_delete(SEXP keyring, SEXP service, SEXP username) {

  const char* empty = "";
  const char* cservice = CHAR(STRING_ELT(service, 0));
  const char* cusername =
    isNull(username) ? empty : CHAR(STRING_ELT(username, 0));

  SecKeychainRef keychain =
    isNull(keyring) ? NULL : keyring_macos_open_keychain(CHAR(STRING_ELT(keyring, 0)));
  SecKeychainItemRef item;

  OSStatus status = SecKeychainFindGenericPassword(
    keychain,
    (UInt32) strlen(cservice), cservice,
    (UInt32) strlen(cusername), cusername,
    /* *passwordLength = */ NULL, /* *passwordData = */ NULL,
    &item);

  if (status != errSecSuccess) {
    if (keychain != NULL) CFRelease(keychain);
    keyring_macos_error("cannot delete password", status);
  }

  status = SecKeychainItemDelete(item);
  if (status != errSecSuccess) {
    if (keychain != NULL) CFRelease(keychain);
    keyring_macos_error("cannot delete password", status);
  }

  if (keychain != NULL) CFRelease(keychain);
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

  /* This should not happen, not a keychain... */
  if (SecKeychainItemGetTypeID() != CFGetTypeID(item)) {
    SET_STRING_ELT(VECTOR_ELT(result, 0), idx, mkChar(""));
    SET_STRING_ELT(VECTOR_ELT(result, 1), idx, mkChar(""));
    return;
  }

  OSStatus status = SecKeychainItemCopyContent(item, &class, &attrList,
					       /* length = */ NULL,
					       /* outData = */ NULL);
  keyring_macos_handle_status("cannot list passwords", status);
  SET_STRING_ELT(VECTOR_ELT(result, 0), idx,
		 mkCharLen(attrs[0].data, attrs[0].length));
  SET_STRING_ELT(VECTOR_ELT(result, 1), idx,
		 mkCharLen(attrs[1].data, attrs[1].length));
  SecKeychainItemFreeContent(&attrList, NULL);
}

CFArrayRef keyring_macos_list_get(const char *ckeyring,
				  const char *cservice) {

  CFStringRef cfservice = NULL;

  CFMutableDictionaryRef query = CFDictionaryCreateMutable(
    kCFAllocatorDefault, 0,
    &kCFTypeDictionaryKeyCallBacks,
    &kCFTypeDictionaryValueCallBacks);

  CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);
  CFDictionarySetValue(query, kSecReturnData, kCFBooleanFalse);
  CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
  CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);

  CFArrayRef searchList = NULL;
  if (ckeyring) {
    SecKeychainRef keychain = keyring_macos_open_keychain(ckeyring);
    searchList = CFArrayCreate(NULL, (const void **) &keychain, 1,
			       &kCFTypeArrayCallBacks);
    CFDictionaryAddValue(query, kSecMatchSearchList, searchList);
  }

  if (cservice) {
    cfservice = CFStringCreateWithBytes(
      /* alloc = */ NULL,
      (const UInt8*) cservice, strlen(cservice),
      kCFStringEncodingUTF8,
      /* isExternalRepresentation = */ 0);
    CFDictionaryAddValue(query, kSecAttrService, cfservice);
  }

  CFArrayRef resArray = NULL;
  OSStatus status = SecItemCopyMatching(query, (CFTypeRef*) &resArray);
  CFRelease(query);
  if (cfservice != NULL) CFRelease(cfservice);
  if (searchList != NULL) CFRelease(searchList);

  /* If there are no elements in the keychain, then SecItemCopyMatching
     returns with an error, so we need work around that and return an
     empty list instead. */

  if (status == errSecItemNotFound) {
    resArray = CFArrayCreate(NULL, NULL, 0, NULL);
    return resArray;

  } else if (status != errSecSuccess) {
    if (resArray != NULL) CFRelease(resArray);
    keyring_macos_handle_status("cannot list passwords", status);
    return NULL;

  } else {
    return resArray;
  }
}

SEXP keyring_macos_list(SEXP keyring, SEXP service) {

  const char *ckeyring =
    isNull(keyring) ? NULL : CHAR(STRING_ELT(keyring, 0));
  const char *cservice =
    isNull(service) ? NULL : CHAR(STRING_ELT(service, 0));

  CFArrayRef resArray = keyring_macos_list_get(ckeyring, cservice);
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

SEXP keyring_macos_create(SEXP keyring, SEXP password) {
  const char *ckeyring = CHAR(STRING_ELT(keyring, 0));
  const char *cpassword = CHAR(STRING_ELT(password, 0));

  SecKeychainRef result = NULL;

  OSStatus status = SecKeychainCreate(
    ckeyring,
    /* passwordLength = */ (UInt32) strlen(cpassword),
    (const void*) cpassword,
    /* promptUser = */ 0, /* initialAccess = */ NULL,
    &result);

  keyring_macos_handle_status("cannot create keychain", status);

  CFArrayRef keyrings = NULL;
  status = SecKeychainCopyDomainSearchList(
    kSecPreferencesDomainUser,
    &keyrings);

  if (status) {
    SecKeychainDelete(result);
    if (result != NULL) CFRelease(result);
    keyring_macos_handle_status("cannot create keychain", status);
  }

  /* We need to add the new keychain to the keychain search list,
     otherwise applications like Keychain Access will not see it.
     There is no API to append it, we need to query the current
     search list, add it, and then set the whole new search list.
     This is of course a race condition. :/ */

  CFIndex count = CFArrayGetCount(keyrings);
  CFMutableArrayRef newkeyrings =
    CFArrayCreateMutableCopy(NULL, count + 1, keyrings);
  CFArrayAppendValue(newkeyrings, result);
  status = SecKeychainSetDomainSearchList(
    kSecPreferencesDomainUser,
    newkeyrings);

  if (status) {
    SecKeychainDelete(result);
    if (result) CFRelease(result);
    if (keyrings) CFRelease(keyrings);
    if (newkeyrings) CFRelease(newkeyrings);
    keyring_macos_handle_status("cannot create keychain", status);
  }

  CFRelease(result);
  CFRelease(keyrings);
  CFRelease(newkeyrings);

  return R_NilValue;
}

SEXP keyring_macos_list_keyring() {
  CFArrayRef keyrings = NULL;
  OSStatus status =
    SecKeychainCopyDomainSearchList(kSecPreferencesDomainUser, &keyrings);
  keyring_macos_handle_status("cannot list keyrings", status);

  CFIndex i, num = CFArrayGetCount(keyrings);

  SEXP result = PROTECT(allocVector(VECSXP, 3));
  SET_VECTOR_ELT(result, 0, allocVector(STRSXP, num));
  SET_VECTOR_ELT(result, 1, allocVector(INTSXP, num));
  SET_VECTOR_ELT(result, 2, allocVector(LGLSXP, num));

  for (i = 0; i < num; i++) {
    SecKeychainRef keychain =
      (SecKeychainRef) CFArrayGetValueAtIndex(keyrings, i);
    UInt32 pathLength = MAXPATHLEN;
    char pathName[MAXPATHLEN + 1];
    status = SecKeychainGetPath(keychain, &pathLength, pathName);
    pathName[pathLength] = '\0';
    if (status) {
      CFRelease(keyrings);
      keyring_macos_handle_status("cannot list keyrings", status);
    }
    SET_STRING_ELT(VECTOR_ELT(result, 0), i, mkCharLen(pathName, pathLength));

    CFArrayRef resArray =
      keyring_macos_list_get(pathName, /* cservice = */ NULL);
    CFIndex numitems = CFArrayGetCount(resArray);
    CFRelease(resArray);
    INTEGER(VECTOR_ELT(result, 1))[i] = (int) numitems;

    SecKeychainStatus kstatus;
    status = SecKeychainGetStatus(keychain, &kstatus);
    if (status) {
      LOGICAL(VECTOR_ELT(result, 2))[i] = NA_LOGICAL;
    } else {
      LOGICAL(VECTOR_ELT(result, 2))[i] =
	! (kstatus & kSecUnlockStateStatus);
    }
  }

  CFRelease(keyrings);

  UNPROTECT(1);
  return result;
}

SEXP keyring_macos_delete_keyring(SEXP keyring) {

  const char *ckeyring = CHAR(STRING_ELT(keyring, 0));

  /* Need to remove it from the search list as well */

  CFArrayRef keyrings = NULL;
  OSStatus status = SecKeychainCopyDomainSearchList(
    kSecPreferencesDomainUser,
    &keyrings);
  keyring_macos_handle_status("cannot delete keyring", status);

  CFIndex i, count = CFArrayGetCount(keyrings);
  CFMutableArrayRef newkeyrings =
    CFArrayCreateMutableCopy(NULL, count, keyrings);
  for (i = 0; i < count; i++) {
    SecKeychainRef item =
      (SecKeychainRef) CFArrayGetValueAtIndex(keyrings, i);
    UInt32 pathLength = MAXPATHLEN;
    char pathName[MAXPATHLEN + 1];
    status = SecKeychainGetPath(item, &pathLength, pathName);
    pathName[pathLength] = '\0';
    if (status) {
      CFRelease(keyrings);
      CFRelease(newkeyrings);
      keyring_macos_handle_status("cannot delete keyring", status);
    }
    if (!strcmp(pathName, ckeyring)) {
      CFArrayRemoveValueAtIndex(newkeyrings, (CFIndex) i);
      status = SecKeychainSetDomainSearchList(
        kSecPreferencesDomainUser,
	newkeyrings);
      if (status) {
	CFRelease(keyrings);
	CFRelease(newkeyrings);
	keyring_macos_handle_status("cannot delete keyring", status);
      }
    }
  }

  /* If we haven't found it on the search list,
     then we just keep silent about it ... */

  CFRelease(keyrings);
  CFRelease(newkeyrings);

  /* And now remove the file as well... */
  SecKeychainRef keychain = keyring_macos_open_keychain(ckeyring);
  status = SecKeychainDelete(keychain);
  CFRelease(keychain);
  keyring_macos_handle_status("cannot delete keyring", status);

  return R_NilValue;
}

SEXP keyring_macos_lock_keyring(SEXP keyring) {
  SecKeychainRef keychain =
    isNull(keyring) ? NULL :
    keyring_macos_open_keychain(CHAR(STRING_ELT(keyring, 0)));
  OSStatus status = SecKeychainLock(keychain);
  if (keychain) CFRelease(keychain);
  keyring_macos_handle_status("cannot lock keychain", status);
  return R_NilValue;
}

SEXP keyring_macos_unlock_keyring(SEXP keyring, SEXP password) {
  const char *cpassword = CHAR(STRING_ELT(password, 0));
  SecKeychainRef keychain =
    isNull(keyring) ? NULL :
    keyring_macos_open_keychain(CHAR(STRING_ELT(keyring, 0)));
  OSStatus status = SecKeychainUnlock(
    keychain,
    (UInt32) strlen(cpassword),
     (const void*) cpassword,
    /* usePassword = */ TRUE);

  if (keychain) CFRelease(keychain);
  keyring_macos_handle_status("cannot unlock keychain", status);
  return R_NilValue;
}

SEXP keyring_macos_is_locked_keyring(SEXP keyring) {
  SecKeychainRef keychain =
    isNull(keyring) ? NULL :
    keyring_macos_open_keychain(CHAR(STRING_ELT(keyring, 0)));

  SecKeychainStatus kstatus;
  OSStatus status = SecKeychainGetStatus(keychain, &kstatus);
  if (status) keyring_macos_error("cannot get lock information", status);

  return ScalarLogical(! (kstatus & kSecUnlockStateStatus));
}

static const R_CallMethodDef callMethods[]  = {
  { "keyring_macos_get",    (DL_FUNC) &keyring_macos_get,            3 },
  { "keyring_macos_set",    (DL_FUNC) &keyring_macos_set,            4 },
  { "keyring_macos_delete", (DL_FUNC) &keyring_macos_delete,         3 },
  { "keyring_macos_list",   (DL_FUNC) &keyring_macos_list,           2 },
  { "keyring_macos_create", (DL_FUNC) &keyring_macos_create,         2 },
  { "keyring_macos_list_keyring",
                            (DL_FUNC) &keyring_macos_list_keyring,   0 },
  { "keyring_macos_delete_keyring",
                            (DL_FUNC) &keyring_macos_delete_keyring, 1 },
  { "keyring_macos_lock_keyring",
                            (DL_FUNC) &keyring_macos_lock_keyring,   1 },
  { "keyring_macos_unlock_keyring",
                            (DL_FUNC) &keyring_macos_unlock_keyring, 2 },
  { "keyring_macos_is_locked_keyring",
                            (DL_FUNC) &keyring_macos_is_locked_keyring, 1 },
  { NULL, NULL, 0 }
};

void R_init_keyring(DllInfo *dll) {
  R_registerRoutines(dll, NULL, callMethods, NULL, NULL);
  R_useDynamicSymbols(dll, FALSE);
  R_forceSymbols(dll, TRUE);
}

#endif // __APPLE__
