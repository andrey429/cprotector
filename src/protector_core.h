#ifndef _PROTECTOR_CORE_
#define _PROTECTOR_CORE_
#endif
#ifndef _PE_COMMONS_
#define _PE_COMMONS_
#include "pe_commons.h"
#endif



#define PROTECTOR_NAME (".protect")
//#define RES_NAME ("\\resource.res")
//#define RES_NAME_LEN (strlen(RES_NAME))

typedef struct _PROTECTION_ENVIRONMENT 
{
	PCHAR pszFilePath;
	DWORD dwFileAttributes;
	DWORD dwFileChecksum;
	DWORD dwMapSize;
	DWORD dwOEP;

} PROTECTION_ENVIRONMENT, *PPROTECTION_ENVIRONMENT;

//ERRORS
#define ERR_PROTECTION_INSTALLED (1)
#define ERR_ENV_NO_ACCESS		 (2)
#define ERR_RESOURCE_NO_ACCESS	 (3)
#define ERR_RESOURCE_CORRUPTED	 (4)
#define ERR_TGT_PATH_NO_ACCESS	 (5)
#define ERR_SUCCESS				 (6)
#define ERR_FILE_NOT_EXECUTABLE  (7)
#define ERR_FILE_NOT_32BIT		 (8)



BOOL ProtectFile(LPSTR pszFile);
BOOL ModifyProtectionSection(SECTION_CONTAINER& scont, PROTECTION_ENVIRONMENT penv);
DWORD SearchForSignature(PBYTE pRawData, DWORD dwRawDataSize, DWORD dwSignature);
BOOL CreateProtectionEnvironment(FILE_DESCR fds, PROTECTION_ENVIRONMENT& prenv);