
#ifdef _WIN32

#include <R.h>
#include <Rinternals.h>

#include <windows.h>
#include <wincred.h>

#include <string.h>

void keyring_wincred_handle_status(const char *func, BOOL status) {
  if (status == FALSE) {
    DWORD errorcode = GetLastError();
    /* TODO: proper error message */
    error("Windows credential store error in '%s': %s", func, "TODO");
  }
}

char* keyring_wincred_create_targetname(SEXP service, SEXP username) {

  const char* empty = "";
  const char* cservice = CHAR(STRING_ELT(service, 0));
  const char* cusername =
    isNull(username) ? empty : CHAR(STRING_ELT(username, 0));
  char* targetname =
    R_alloc(1, strlen(cservice) + strlen(cusername) + 2);

  if (!targetname) error("Out of memory");

  strcpy(targetname, cservice);
  if (!isNull(username)) {
    strcat(targetname, ":");
    strcat(targetname, cusername);
  }

  return targetname;
}

SEXP keyring_wincred_get(SEXP service, SEXP username) {

  const char* targetname =
    keyring_wincred_create_targetname(service, username);
  CREDENTIAL* cred;
  SEXP result;

  BOOL status = CredRead(targetname, CRED_TYPE_GENERIC,
			 /* Flags = */ 0, &cred);

  keyring_wincred_handle_status("get", status);

  result = PROTECT(ScalarString(mkCharLen(
    (const char*) cred->CredentialBlob,
    cred->CredentialBlobSize)));

  CredFree(cred);

  UNPROTECT(1);
  return result;
}

SEXP keyring_wincred_set(SEXP service, SEXP username, SEXP password) {

  char* targetname =
    keyring_wincred_create_targetname(service, username);
  const char* cpassword = CHAR(STRING_ELT(password, 0));
  CREDENTIAL cred = { 0 };
  BOOL status;

  cred.Type = CRED_TYPE_GENERIC;
  cred.TargetName = targetname;
  cred.CredentialBlobSize = strlen(cpassword);
  cred.CredentialBlob = (LPBYTE) cpassword;
  cred.Persist = CRED_PERSIST_LOCAL_MACHINE;

  status = CredWrite(&cred, /* Flags = */ 0);

  keyring_wincred_handle_status("set", status);

  return R_NilValue;
}

SEXP keyring_wincred_delete(SEXP service, SEXP username) {

  const char* targetname =
    keyring_wincred_create_targetname(service, username);

  BOOL status = CredDelete(targetname, CRED_TYPE_GENERIC,
			   /* Flags = */ 0);

  keyring_wincred_handle_status("delete", status);

  return R_NilValue;
}

SEXP keyring_wincred_list(SEXP service) {

  const char *empty = "*";
  const char *cservice =
    isNull(service) ? empty : CHAR(STRING_ELT(service, 0));
  char *filter =
    isNull(service) ? (char*) empty : R_alloc(1, strlen(cservice) + 3);

  DWORD count;
  PCREDENTIAL *creds = NULL;

  if (!cservice || !filter) error("Out of memory");

  if (!isNull(service)) {
    strcpy(filter, cservice);
    strcat(filter, ":*");
  }

  BOOL status = CredEnumerate(filter, /* Flags = */ 0, &count,
			      &creds);

  if (status == FALSE) {
    if (creds != NULL) CredFree(creds);
    keyring_wincred_handle_status("list", status);
    return R_NilValue;

  } else {
    SEXP result = PROTECT(allocVector(VECSXP, 2));
    size_t i, num = (size_t) count;
    SET_VECTOR_ELT(result, 0, allocVector(STRSXP, num));
    SET_VECTOR_ELT(result, 1, allocVector(STRSXP, num));
    for (i = 0; i < count; i++) {
      char *target = creds[i]->TargetName;
      char *sep = strchr(target, ':');
      if (!sep) {
	SET_STRING_ELT(VECTOR_ELT(result, 0), i, mkChar(target));
	SET_STRING_ELT(VECTOR_ELT(result, 1), i, mkChar(""));
      } else {
	SET_STRING_ELT(VECTOR_ELT(result, 0), i,
		       mkCharLen(target, sep - target));
	SET_STRING_ELT(VECTOR_ELT(result, 1), i, mkChar(sep + 1));
      }
    }
    CredFree(creds);

    UNPROTECT(1);
    return result;
  }
}

#endif // _WIN32
