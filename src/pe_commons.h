#ifndef _PE_COMMONS_
#define _PE_COMMONS_
#endif

#ifndef _WINDOWS_
#include <windows.h>
#endif

#ifndef _IMAGEHLP_
#include <imagehlp.h>
#endif

#define MEM_NOT_SPECIFIED (0)
#define MEM_EXEC_READ_WRITE_CODE (0xE0000020)
#define MEM_DATA				 (0xC0000040)

typedef struct SECTION_CONTAINER_STRUCT 
{
	
	IMAGE_SECTION_HEADER scnHeader;
	PBYTE pScnRawData;

}	SECTION_CONTAINER, *PSECTION_CONTAINER;

typedef struct FILE_DESCRIPTOR_STRUCT 
{
	HANDLE hFileHandle;
	HANDLE hMapHandle;
	LPVOID lpImageBase;
	DWORD dwInitialFileSize;
	LPSTR pszFullFileName;
	DWORD dwFilePathLength;

} FILE_DESCR, *PFILE_DESCR;
typedef struct ACCESS_DESCRIPTOR_STRUCT 
{
	DWORD dwFileHandleAccess;
	DWORD dwMapHandleAccess;
	DWORD dwMemoryMapObjectAccess;
	DWORD dwShareMode;

} ACCESS_DESCR, *PACCESS_DESCR;

/*
	returns:
	PIMAGE_DOS_HEADER if file has MZ signature
	NULL otherwise
*/
PIMAGE_DOS_HEADER GetDOSHeader(FILE_DESCR fds);
/*
	returns:
	PIMAGE_NT_HEADERS32 if file has PE signature
	NULL otherwise
*/
PIMAGE_NT_HEADERS32 GetNTHeaders(FILE_DESCR fds);
/*
	returns:
	PIMAGE_SECTION_HEADER of section[idx] if file has section[idx]
	NULL otherwise
*/
PIMAGE_SECTION_HEADER GetSectionHdrByIdx(FILE_DESCR fds, DWORD idx);
/*
	returns:
	TRUE if file is 32 bit PE
	FALSE otherwise
*/
BOOL IsWin32Executable(FILE_DESCR fds);
/*
	returns: none
	deletes bound import records in DataDirectory
*/
VOID DeleteBoundImports(PIMAGE_NT_HEADERS32 pNTHeader);
/*
	returns:
	TRUE if section is added
	FALSE otherwise
	
	remarks:
	HANDLE should be assigned RW access, MapView should be protectes FILE_MAP_READ | FILE_MAP_WRITE

*/

BOOL AddNewSection(FILE_DESCR sFileDescr, SECTION_CONTAINER tgtScnUnion, PCSTR scnName, DWORD dwSectCharacteristics);
/*
	returns: none
	changes entry point to dwNewEP and stores original in pdwOEP
*/
VOID ChangeEntryPoint(FILE_DESCR fds, DWORD dwNewEP, DWORD& dwOEP);
/*
	returns: 
	tries to get sectionHdr[idx] AND section[idx], returns [idx] if possible
	returns DWORD(-1) otherwise
	
*/
DWORD GetSectionContainerByIdx(SECTION_CONTAINER& scnCnt, DWORD idx, FILE_DESCR sFileDescr);
/*
	returns:
	TRUE, if whole descriptor created
	FALSE, otherwise
*/

BOOL CreateFileDescriptor(LPSTR pszFilePath, FILE_DESCR& fds, ACCESS_DESCR acds);

/*
	returns: none
	closes the whole desciptor
*/

VOID CloseFileDescriptor(FILE_DESCR& fds);
/*
	returns: none
	creates read-write access descriptor
*/
VOID CreateReadWriteAccessDescr(ACCESS_DESCR& acds);
/*	
	returns:
	number of sections in exe,
	0 if not 32 bit exe
*/
DWORD GetNumberOfSections(FILE_DESCR fds);
/*
	returns:
	TRUE on successful creation
	FALSE otherwise
*/
BOOL GetSelfFileDescriptor(FILE_DESCR& fds);
/*
	returns:
	TRUE on success getting the section[idx] 
	FALSE otherwise

*/

//BOOL GetSectionContainerByIdxFromSelf(SECTION_CONTAINER& scont, DWORD idx);
/*
returns:
Creates non-exclusive read access
*/
VOID CreateReadAccessDescriptor(ACCESS_DESCR& acds);