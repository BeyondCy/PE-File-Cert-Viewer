/*
ooo        ooooo               .   oooo                                   
`88.       .888'             .o8   `888                                   
 888b     d'888   .oooo.   .o888oo  888 .oo.    .ooooo.  oooo oooo    ooo 
 8 Y88. .P  888  `P  )88b    888    888P"Y88b  d88' `88b  `88. `88.  .8'  
 8  `888'   888   .oP"888    888    888   888  888ooo888   `88..]88..8'   
 8    Y     888  d8(  888    888 .  888   888  888    .o    `888'`888'    
o8o        o888o `Y888""8o   "888" o888o o888o `Y8bod8P'     `8'  `8'     
*/                                                                  

#include <windows.h>
#include <Imagehlp.h>
#include <Wintrust.h>
#include <Wincrypt.h>
#include <Shlwapi.h>
#include <stdio.h>

DWORD dwError;

typedef struct NT_PFXARRAY{
	DWORD dwSize;
	DWORD dwCount;
	LPVOID lpHeap;
	LPWIN_CERTIFICATE pCertificate;
} PFX_ARRAY, *PPFX_ARRAY;

BOOL PfxGetWinCertificate(PPFX_ARRAY pArray, HANDLE hFileHandle, HANDLE hHeap);
BOOL PfxGetCertificationDataEx(PCCERT_CONTEXT pCert, DWORD dwIndex);
LPSTR* WINAPI CommandLineToArgvA(LPSTR lpCmdline, INT* numargs);

int WINAPI WinMain (HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nShowCmd)
{
	HANDLE hHeap = GetProcessHeap();
	PFX_ARRAY HeaderData = {0};
	HANDLE hFileHandle;
	dwError = ERROR_SUCCESS;
	HCERTSTORE hStore = NULL;
	CRYPT_DATA_BLOB cdBlob;
	CERT_ENHKEY_USAGE cUsage;
	TCHAR szCodeSigningOid[] = szOID_PKIX_KP_CODE_SIGNING;
	PCCERT_CONTEXT pCertContext = NULL;
	
	INT ArgC = 0;
	LPSTR *ArgV = CommandLineToArgvA(GetCommandLineA(), &ArgC);
	
	if(ArgV[1] != NULL)
	{
		if(!PathFileExists(ArgV[1]))
		{
			SetLastError(ERROR_PATH_NOT_FOUND);
			goto FAILURE;
		}
	}
	
	hFileHandle = CreateFile(ArgV[1], GENERIC_READ | GENERIC_WRITE,
							 0x00000000, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
					
	if(hFileHandle == INVALID_HANDLE_VALUE)
		goto FAILURE;

	if(!PfxGetWinCertificate(&HeaderData, hFileHandle, hHeap))
		goto FAILURE;
	
	cdBlob.cbData = HeaderData.dwSize - sizeof(DWORD) - sizeof(WORD) - sizeof(WORD);
	cdBlob.pbData = HeaderData.pCertificate->bCertificate;
	dwError = ERROR_SUCCESS;
	
	hStore = CertOpenStore(CERT_STORE_PROV_PKCS7, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, &cdBlob);
	if(hStore == NULL)
		goto FAILURE;
	
	cUsage.cUsageIdentifier = 0x01;
	cUsage.rgpszUsageIdentifier = (LPSTR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(LPTSTR));
	cUsage.rgpszUsageIdentifier[0] = &szCodeSigningOid[0];
	dwError = ERROR_SUCCESS;
	
	pCertContext = CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
											  CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, CERT_FIND_ENHKEY_USAGE,
											  &cUsage, pCertContext);
	
	while(pCertContext)
	{			  
		if(pCertContext)
		{
			dwError++;
			if(!PfxGetCertificationDataEx(pCertContext, dwError))
				goto FAILURE;
		}
		
		pCertContext = CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
												  CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, CERT_FIND_ENHKEY_USAGE,
												  &cUsage, pCertContext);
	
	}
	
	if(dwError == 0)
		printf("No cert found.\r\n");

	
	if(HeaderData.pCertificate)
		HeapFree(hHeap, HEAP_ZERO_MEMORY, HeaderData.pCertificate);
		
	if(hFileHandle)
		CloseHandle(hFileHandle);
		
	if(hStore != NULL)
		CertCloseStore(hStore, 0);
	
	LocalFree(ArgV);

	return ERROR_SUCCESS;
	
FAILURE:
	
	dwError = GetLastError();
	
	if(hFileHandle)
		CloseHandle(hFileHandle);
		
	if(HeaderData.pCertificate->bCertificate)
		HeapFree(hHeap, HEAP_ZERO_MEMORY, HeaderData.pCertificate);
		
	if(hStore != NULL)
		CertCloseStore(hStore, 0);
	
	LocalFree(ArgV);
		
	printf("%x -- %ld\r\n", dwError, dwError);
		
	system("PAUSE");
	return dwError;
}

BOOL PfxGetWinCertificate(PPFX_ARRAY pArray, HANDLE hFileHandle, HANDLE hHeap)
{
	if((!ImageEnumerateCertificates(hFileHandle, CERT_SECTION_TYPE_ANY, &pArray->dwCount, NULL, 0)) && (pArray->dwCount == 0))
		goto FAILURE;

	SetLastError(0x7A);
	while(GetLastError() == 0x7A)
	{
		pArray->pCertificate = (LPWIN_CERTIFICATE)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, pArray->dwSize + 1);
		if(pArray->pCertificate == NULL)
			goto FAILURE;
				
		if((!ImageGetCertificateData(hFileHandle, 0, pArray->pCertificate, &pArray->dwSize) && GetLastError() != 0x7A))
			goto FAILURE;
	}

	pArray->pCertificate->bCertificate[pArray->pCertificate->dwLength] = 0x00;
	
	return TRUE;

FAILURE:
	
	return FALSE;
}

BOOL PfxGetCertificationDataEx(PCCERT_CONTEXT pCert, DWORD dwIndex)
{
	DWORD dwString = CERT_X500_NAME_STR;
	LPVOID szHeap = NULL;
	HANDLE hHeap = GetProcessHeap();
	DWORD dwCount = ERROR_SUCCESS;
	
	dwCount = CertGetNameString(pCert, CERT_NAME_RDN_TYPE, 0, &dwString, NULL, 0);
	if(dwCount <= 1)
		goto FAILURE;
	
	szHeap = (LPTSTR)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwCount * sizeof(TCHAR));
	if(szHeap == NULL)
		goto FAILURE;
	
	dwCount = CertGetNameString(pCert, CERT_NAME_RDN_TYPE, 0, &dwString, szHeap, dwCount);
	
	if(dwCount)
		printf("%ld - %s\r\n", dwIndex, szHeap);
		
	HeapFree(hHeap, HEAP_ZERO_MEMORY, szHeap);
	return TRUE;
	
FAILURE:

	if(szHeap == NULL)
		HeapFree(hHeap, HEAP_ZERO_MEMORY, szHeap);
		
	return FALSE;
	
}



/*************************************************************************
 * CommandLineToArgvA            [SHELL32.@]
 * 
 * MODIFIED FROM https://www.winehq.org/ project
 * We must interpret the quotes in the command line to rebuild the argv
 * array correctly:
 * - arguments are separated by spaces or tabs
 * - quotes serve as optional argument delimiters
 *   '"a b"'   -> 'a b'
 * - escaped quotes must be converted back to '"'
 *   '\"'      -> '"'
 * - consecutive backslashes preceding a quote see their number halved with
 *   the remainder escaping the quote:
 *   2n   backslashes + quote -> n backslashes + quote as an argument delimiter
 *   2n+1 backslashes + quote -> n backslashes + literal quote
 * - backslashes that are not followed by a quote are copied literally:
 *   'a\b'     -> 'a\b'
 *   'a\\b'    -> 'a\\b'
 * - in quoted strings, consecutive quotes see their number divided by three
 *   with the remainder modulo 3 deciding whether to close the string or not.
 *   Note that the opening quote must be counted in the consecutive quotes,
 *   that's the (1+) below:
 *   (1+) 3n   quotes -> n quotes
 *   (1+) 3n+1 quotes -> n quotes plus closes the quoted string
 *   (1+) 3n+2 quotes -> n+1 quotes plus closes the quoted string
 * - in unquoted strings, the first quote opens the quoted string and the
 *   remaining consecutive quotes follow the above rule.
 */

LPSTR* WINAPI CommandLineToArgvA(LPSTR lpCmdline, INT* numargs)
{
    DWORD argc;
    LPSTR  *argv;
    LPSTR s;
    LPSTR d;
    LPSTR cmdline;
    int qcount,bcount;

    if(!numargs || *lpCmdline==0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    /* --- First count the arguments */
    argc=1;
    s=lpCmdline;
    /* The first argument, the executable path, follows special rules */
    if (*s=='"')
    {
        /* The executable path ends at the next quote, no matter what */
        s++;
        while (*s)
            if (*s++=='"')
                break;
    }
    else
    {
        /* The executable path ends at the next space, no matter what */
        while (*s && *s!=' ' && *s!='\t')
            s++;
    }
    /* skip to the first argument, if any */
    while (*s==' ' || *s=='\t')
        s++;
    if (*s)
        argc++;

    /* Analyze the remaining arguments */
    qcount=bcount=0;
    while (*s)
    {
        if ((*s==' ' || *s=='\t') && qcount==0)
        {
            /* skip to the next argument and count it if any */
            while (*s==' ' || *s=='\t')
                s++;
            if (*s)
                argc++;
            bcount=0;
        }
        else if (*s=='\\')
        {
            /* '\', count them */
            bcount++;
            s++;
        }
        else if (*s=='"')
        {
            /* '"' */
            if ((bcount & 1)==0)
                qcount++; /* unescaped '"' */
            s++;
            bcount=0;
            /* consecutive quotes, see comment in copying code below */
            while (*s=='"')
            {
                qcount++;
                s++;
            }
            qcount=qcount % 3;
            if (qcount==2)
                qcount=0;
        }
        else
        {
            /* a regular character */
            bcount=0;
            s++;
        }
    }

    /* Allocate in a single lump, the string array, and the strings that go
     * with it. This way the caller can make a single LocalFree() call to free
     * both, as per MSDN.
     */
    argv=LocalAlloc(LMEM_FIXED, (argc+1)*sizeof(LPSTR)+(strlen(lpCmdline)+1)*sizeof(char));
    if (!argv)
        return NULL;
    cmdline=(LPSTR)(argv+argc+1);
    strcpy(cmdline, lpCmdline);

    /* --- Then split and copy the arguments */
    argv[0]=d=cmdline;
    argc=1;
    /* The first argument, the executable path, follows special rules */
    if (*d=='"')
    {
        /* The executable path ends at the next quote, no matter what */
        s=d+1;
        while (*s)
        {
            if (*s=='"')
            {
                s++;
                break;
            }
            *d++=*s++;
        }
    }
    else
    {
        /* The executable path ends at the next space, no matter what */
        while (*d && *d!=' ' && *d!='\t')
            d++;
        s=d;
        if (*s)
            s++;
    }
    /* close the executable path */
    *d++=0;
    /* skip to the first argument and initialize it if any */
    while (*s==' ' || *s=='\t')
        s++;
    if (!*s)
    {
        /* There are no parameters so we are all done */
        argv[argc]=NULL;
        *numargs=argc;
        return argv;
    }

    /* Split and copy the remaining arguments */
    argv[argc++]=d;
    qcount=bcount=0;
    while (*s)
    {
        if ((*s==' ' || *s=='\t') && qcount==0)
        {
            /* close the argument */
            *d++=0;
            bcount=0;

            /* skip to the next one and initialize it if any */
            do {
                s++;
            } while (*s==' ' || *s=='\t');
            if (*s)
                argv[argc++]=d;
        }
        else if (*s=='\\')
        {
            *d++=*s++;
            bcount++;
        }
        else if (*s=='"')
        {
            if ((bcount & 1)==0)
            {
                /* Preceded by an even number of '\', this is half that
                 * number of '\', plus a quote which we erase.
                 */
                d-=bcount/2;
                qcount++;
            }
            else
            {
                /* Preceded by an odd number of '\', this is half that
                 * number of '\' followed by a '"'
                 */
                d=d-bcount/2-1;
                *d++='"';
            }
            s++;
            bcount=0;
            /* Now count the number of consecutive quotes. Note that qcount
             * already takes into account the opening quote if any, as well as
             * the quote that lead us here.
             */
            while (*s=='"')
            {
                if (++qcount==3)
                {
                    *d++='"';
                    qcount=0;
                }
                s++;
            }
            if (qcount==2)
                qcount=0;
        }
        else
        {
            /* a regular character */
            *d++=*s++;
            bcount=0;
        }
    }
    *d='\0';
    argv[argc]=NULL;
    *numargs=argc;

    return argv;
}
