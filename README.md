# PE File Cert Viewer


NOTE: This application was compiled using the DEV C++ IDE (formally known as Bloodshed).

0. CommandLineArgvA was barrowed from WinHQ. Thanks for the wonderful code!

1. On launch the application expects 1 argument. This argument is to be the full path to the executable module to be tested for a signature. The file paths validity is tested and, if the path is invalid, the last error is set to ERROR_PATH_NOT_FOUND and goes to the failure routine.

2. The application gets a handle on the passed parameter. If the file is currently running and the dwShareMode on the file is set to zero or the file is locked, the application may fail.

3. If CreateFile returns a valid handle the application calls the PfxGetWinCertificate function with the passed parameters being our HeaderData structure (type: NT_PFXARRAY), the handle to file returned from CreateFile and a Heap handle returned from GetProcessHeap(). The first function call is ImageEnumerateCertificates with the flag being set to CERT_SECTION_TYPE_ANY. If ImageEnumerateCertificates returns TRUE the application allocates a structure (LPWIN_CERTIFICATE) from the TYPEDEF NT_PFXARRAY structure.

4. If the application successfully allocates a buffer from the process memory pool, a subsequent function call is made from ImageGetCertificateData. If the function call fails we go to our failure routine. The memory is not freed in this current instance and will be freed in our main function failure routine.

5. Upon success, the application will a call to CertOpenStore in preparation to lookup the values loaded from PfxGetWinCertificate. Before the call is made the CRYPT_DATA_BLOB structure members are set to their appropriate values defined on MSDN. If the call to CertOpenStore fails, the application jumps to its failure routine. DWORD dwError is set to ERROR_SUCCESS (zero) is preparation to interate through data later on.

6. CERT_ENHKEY_USAGE values are set to their appropriate values as defined from MSDN. We then make a call to CertFindCertificateInStore to lookup the signature data.

7. If the call to CertFindCertificateInStore is successful, the value of pCertContext (PCCERT_CONTEXT) will not be NULL. Hence, the application will increment dwError by 1 and make a call to PfxGetCertificationDataEx with the Index being dwError. This function retrieves the certificate name and certificate string values.

8. If PfxGetCertificationDataEx is successful, we made a subsequent call to CertFindCertificateInStore to iterate to the next certificate in our loaded module.

9. If no certificates are found from CertFindCertificateInStore dwError remains zero and our application goes to its failure routine.

10. If the application succeeeds in loading all data, the values are printed, all data is freed, and the application terminates with ERROR_SUCCESS (zero).


If you have any questions or comments or simply want to connect, add me on LinkedIn! https://www.linkedin.com/in/ma1thew/









