#include "pe_commons.h"


/*
	returns:
	PIMAGE_DOS_HEADER if file has MZ signature
	NULL otherwise
*/
PIMAGE_DOS_HEADER GetDOSHeader(FILE_DESCR fds)
{
	LPVOID lpImageBase = fds.lpImageBase;
	return (((PIMAGE_DOS_HEADER) lpImageBase)->e_magic == IMAGE_DOS_SIGNATURE) ? 
		(PIMAGE_DOS_HEADER) lpImageBase : NULL;
}
/*
	returns:
	PIMAGE_NT_HEADERS32 if file has PE signature
	NULL otherwise
*/
PIMAGE_NT_HEADERS32 GetNTHeaders(FILE_DESCR fds)
{
	LPVOID lpImageBase = fds.lpImageBase;
	PIMAGE_DOS_HEADER pDosHdr;
	if	(!(pDosHdr = GetDOSHeader(fds))) return NULL;
	
	PIMAGE_NT_HEADERS32 pnt = (PIMAGE_NT_HEADERS32) 
		((DWORD) lpImageBase + pDosHdr->e_lfanew);
	
	return pnt->Signature == IMAGE_NT_SIGNATURE && 
		pnt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC
		? pnt : NULL;
}
/*
	returns:
	PIMAGE_SECTION_HEADER of section[idx] if file has section[idx]
	NULL otherwise
*/
PIMAGE_SECTION_HEADER GetSectionHdrByIdx(FILE_DESCR fds, DWORD idx)
{
	PIMAGE_NT_HEADERS32 pNTHdr;
	PIMAGE_SECTION_HEADER pSecHdr;
	LPVOID lpImageBase = fds.lpImageBase;
	if	(!(pNTHdr = GetNTHeaders(fds))) return NULL;
	if	(idx > pNTHdr->FileHeader.NumberOfSections) return NULL;
	pSecHdr = IMAGE_FIRST_SECTION(pNTHdr);
	while	(idx-- > 0)
	{
		pSecHdr++;
	}
	return pSecHdr;

}
/*
	returns:
	TRUE if file is 32 bit PE
	FALSE otherwise
*/
BOOL IsWin32Executable(FILE_DESCR fds)
{
	return GetNTHeaders(fds) ? TRUE : FALSE;
}
/*
	returns: none
	deletes bound import records in DataDirectory
*/
VOID DeleteBoundImports(PIMAGE_NT_HEADERS32 pNTHeader)
{
	pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
	pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
}
/*
	returns:
	TRUE if section is added
	FALSE otherwise
	
	remarks:
	HANDLE should be assigned RW access, MapView should be protectes FILE_MAP_READ | FILE_MAP_WRITE

*/

/*BOOL AddNewSection(FILE_DESCR fds, SECTION_CONTAINER tgtScnUnion,
				   PCSTR scnName, DWORD dwSectCharacteristics)
{
	DWORD dwMaxIdx = 0, dwNewScnHdrAddr = 0, dwTemp = 0;
	PIMAGE_SECTION_HEADER pScn;
	PIMAGE_NT_HEADERS32 pNT;
	HANDLE hFile = fds.hFileHandle;
	LPVOID lpImageBase = fds.lpImageBase;
	
	if	(hFile == INVALID_HANDLE_VALUE || hFile == NULL || lpImageBase == NULL) return FALSE;
	if	(!	(pNT = GetNTHeaders(fds))) return FALSE;
	if	(!	(pScn = GetSectionHdrByIdx(fds, 0))) return FALSE;
	
	for	(DWORD i = 0; i < pNT->FileHeader.NumberOfSections; i++)
	{
		if	(pScn[i].VirtualAddress > pScn->VirtualAddress)
		{
			dwMaxIdx = i;
		}
	}
	DeleteBoundImports(pNT);
	
	IMAGE_SECTION_HEADER modifiedScnHdr;
	ZeroMemory(&modifiedScnHdr, sizeof(IMAGE_SECTION_HEADER));
	if(dwSectCharacteristics == MEM_NOT_SPECIFIED)
	{
		modifiedScnHdr.Characteristics = tgtScnUnion.scnHeader.Characteristics;
	}
	else
	{
		modifiedScnHdr.Characteristics = dwSectCharacteristics;
	}
	modifiedScnHdr.Misc.VirtualSize = tgtScnUnion.scnHeader.Misc.VirtualSize;
	if	(strlen(scnName) < 8)
	{
		memcpy(modifiedScnHdr.Name, scnName, strlen(scnName));
	} 
	else
	{
		memcpy(modifiedScnHdr.Name, scnName, 8);
	}
	modifiedScnHdr.PointerToRawData = GetFileSize(hFile, NULL);
	modifiedScnHdr.SizeOfRawData = tgtScnUnion.scnHeader.SizeOfRawData;
	modifiedScnHdr.VirtualAddress = 
		pScn[dwMaxIdx].VirtualAddress + ((pScn[dwMaxIdx].Misc.VirtualSize)&0xfffff000) + 0x1000;
	
	

	

	dwNewScnHdrAddr = (DWORD) &pScn[pNT->FileHeader.NumberOfSections - 1] 
	+ sizeof(IMAGE_SECTION_HEADER) - (DWORD) lpImageBase;
	

	SetFilePointer(hFile, dwNewScnHdrAddr, NULL, FILE_BEGIN);
	if	(!WriteFile(hFile, &modifiedScnHdr, sizeof(IMAGE_SECTION_HEADER), &dwTemp, NULL))
	{
		return FALSE;
	}
	SetFilePointer(hFile, modifiedScnHdr.PointerToRawData, NULL, FILE_BEGIN);
	if	(!WriteFile(hFile, tgtScnUnion.pScnRawData, modifiedScnHdr.SizeOfRawData, &dwTemp, NULL))
	{
		return FALSE;
	}
	
	pNT->FileHeader.NumberOfSections++;
	pNT->OptionalHeader.SizeOfImage = modifiedScnHdr.VirtualAddress + modifiedScnHdr.Misc.VirtualSize;

	SetFilePointer(hFile, FILE_BEGIN, 0, FILE_BEGIN);
	return TRUE;

}*/
BOOL AddNewSection(FILE_DESCR fds, SECTION_CONTAINER tgtScnUnion,//edited
				   PCSTR scnName, DWORD dwSectCharacteristics)
{
	DWORD dwMaxIdx = 0, dwNewScnHdrAddr = 0, dwTemp = 0;
	PIMAGE_SECTION_HEADER pScn;
	PIMAGE_NT_HEADERS32 pNT;
	HANDLE hFile = fds.hFileHandle;
	LPVOID lpImageBase = fds.lpImageBase;
	
	if	(hFile == INVALID_HANDLE_VALUE || hFile == NULL || lpImageBase == NULL) return FALSE;
	if	(!	(pNT = GetNTHeaders(fds))) return FALSE;
	if	(!	(pScn = GetSectionHdrByIdx(fds, 0))) return FALSE;
	
	for	(DWORD i = 0; i < pNT->FileHeader.NumberOfSections; i++)
	{
		if	(pScn[i].VirtualAddress + pScn[i].Misc.VirtualSize > pScn->VirtualAddress + pScn->Misc.VirtualSize)
		{
			dwMaxIdx = i;
		}
	}
	DeleteBoundImports(pNT);
	
	IMAGE_SECTION_HEADER modifiedScnHdr;
	ZeroMemory(&modifiedScnHdr, sizeof(IMAGE_SECTION_HEADER));
	if(dwSectCharacteristics == MEM_NOT_SPECIFIED)
	{
		modifiedScnHdr.Characteristics = tgtScnUnion.scnHeader.Characteristics;
	}
	else
	{
		modifiedScnHdr.Characteristics = dwSectCharacteristics;
	}
	
	modifiedScnHdr.Misc.VirtualSize = tgtScnUnion.scnHeader.Misc.VirtualSize;
	ZeroMemory(modifiedScnHdr.Name, 8);

	if	(strlen(scnName) < 8)
	{
		memcpy(modifiedScnHdr.Name, scnName, strlen(scnName));
	} 
	else
	{
		memcpy(modifiedScnHdr.Name, scnName, 8);
	}

	//modifiedScnHdr.PointerToRawData = GetFileSize(hFile, NULL);//TODO makealign!!!
	//modifiedScnHdr.SizeOfRawData = tgtScnUnion.scnHeader.SizeOfRawData;
//	;формула для вычисления размера с учетом выравнивания 
//; (x+(y-1))&(~(y-1)), где x -;размер без выравнивания, 
	DWORD dwPointerToRawData = GetFileSize(hFile, NULL);
	DWORD dwFileAlign = pNT->OptionalHeader.FileAlignment;
	DWORD dwAlignedSize = (dwPointerToRawData + dwFileAlign - 1)&(~(dwFileAlign-1));
	DWORD dwAddSpaceCount = dwAlignedSize - dwPointerToRawData;

	if(dwAddSpaceCount != 0)
	{
		PBYTE buf = (PBYTE) malloc (dwAddSpaceCount);
		DWORD dwCount;
		ZeroMemory(buf, dwAddSpaceCount);
		SetFilePointer(hFile, dwPointerToRawData, NULL, FILE_BEGIN);
		if(!WriteFile(hFile, buf, dwAddSpaceCount, &dwCount, NULL)) return FALSE;
	}
	
	modifiedScnHdr.PointerToRawData = dwAlignedSize;
	modifiedScnHdr.SizeOfRawData = tgtScnUnion.scnHeader.SizeOfRawData;
	//modifiedScnHdr.VirtualAddress = 
	//	pScn[dwMaxIdx].VirtualAddress + ((pScn[dwMaxIdx].Misc.VirtualSize)&0xfffff000) + 0x1000;
	DWORD dwPrevImageSize = pScn[dwMaxIdx].VirtualAddress + pScn[dwMaxIdx].Misc.VirtualSize;

	modifiedScnHdr.VirtualAddress = (dwPrevImageSize + pNT->OptionalHeader.SectionAlignment - 1)&
		(~(pNT->OptionalHeader.SectionAlignment - 1));
	

	dwNewScnHdrAddr = (DWORD) &pScn[pNT->FileHeader.NumberOfSections - 1] 
	+ sizeof(IMAGE_SECTION_HEADER) - (DWORD) lpImageBase;
	

	SetFilePointer(hFile, dwNewScnHdrAddr, NULL, FILE_BEGIN);
	if	(!WriteFile(hFile, &modifiedScnHdr, sizeof(IMAGE_SECTION_HEADER), &dwTemp, NULL))
	{
		return FALSE;
	}
	SetFilePointer(hFile, modifiedScnHdr.PointerToRawData, NULL, FILE_BEGIN);
	if	(!WriteFile(hFile, tgtScnUnion.pScnRawData, modifiedScnHdr.SizeOfRawData, &dwTemp, NULL))
	{
		return FALSE;
	}
	
	pNT->FileHeader.NumberOfSections++;
	pNT->OptionalHeader.SizeOfImage = modifiedScnHdr.VirtualAddress + modifiedScnHdr.Misc.VirtualSize;
	SetFilePointer(hFile, FILE_BEGIN, 0, FILE_BEGIN);
	return TRUE;

}
/*
	returns: none
	changes entry point to dwNewEP and stores original in pdwOEP
*/
VOID ChangeEntryPoint(FILE_DESCR fds, DWORD dwNewEP, DWORD& dwOEP)
{
	LPVOID lpImageBase = fds.lpImageBase;
	PIMAGE_NT_HEADERS32 pNT = GetNTHeaders(fds);
	if(pNT->Signature != IMAGE_NT_SIGNATURE)

	{
		MessageBoxA(NULL, "BAD CHANGE!", 0, 0);
	}
	dwOEP = pNT->OptionalHeader.AddressOfEntryPoint;
	pNT->OptionalHeader.AddressOfEntryPoint = dwNewEP;
}
/*
	returns: 
	tries to get sectionHdr[idx] AND section[idx], returns [idx] if possible
	returns DWORD(-1) otherwise
	
*/
DWORD GetSectionContainerByIdx(SECTION_CONTAINER& scnCnt, DWORD idx, FILE_DESCR fds)
{
	HANDLE hFile = fds.hFileHandle;
	LPVOID lpImageBase = fds.lpImageBase;
	PIMAGE_SECTION_HEADER pScnHdr;
	DWORD dwTemp = 0;
	if	(!(pScnHdr = GetSectionHdrByIdx(fds, idx)))
	{
		return (DWORD) -1;
	}
	ZeroMemory(&scnCnt, sizeof(scnCnt));
	memcpy(&scnCnt.scnHeader, pScnHdr, sizeof(IMAGE_SECTION_HEADER));
//	if	(IsBadWritePtr(scnCnt.pScnRawData, pScnHdr->SizeOfRawData))
//	{
		
//		free(scnCnt.pScnRawData);
		scnCnt.pScnRawData = (PBYTE) malloc (pScnHdr->SizeOfRawData);
//	}
	SetFilePointer(hFile, pScnHdr->PointerToRawData, NULL, FILE_BEGIN);
	if	(!ReadFile(hFile, scnCnt.pScnRawData, pScnHdr->SizeOfRawData ,&dwTemp, NULL))
	{
		return DWORD(-1);
	}
	return idx;

}


/*
	returns:
	TRUE, if whole descriptor created
	FALSE, otherwise
*/

BOOL CreateFileDescriptor(LPSTR pszFilePath, FILE_DESCR& fds, ACCESS_DESCR acds)
{
	HANDLE hFile;
	HANDLE hMap;
	LPVOID lpImageBase;
	DWORD dwInitialFileSize;
	hFile = CreateFileA(pszFilePath, acds.dwFileHandleAccess, 
		acds.dwShareMode, NULL, OPEN_EXISTING, 0, NULL);
	if	(hFile == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
		return FALSE;
	}
	hMap = CreateFileMappingA(hFile, NULL, acds.dwMapHandleAccess, 0, 0, NULL);
	if	(hMap == NULL)
	{
		CloseHandle(hMap);
		CloseHandle(hFile);
		return FALSE;
	}
	dwInitialFileSize = GetFileSize(hFile, NULL);
	lpImageBase = MapViewOfFile(hMap, acds.dwMemoryMapObjectAccess, 0, 0, dwInitialFileSize);
	if	(lpImageBase == NULL)
	{
		UnmapViewOfFile(lpImageBase);
		CloseHandle(hMap);
		CloseHandle(hFile);
		return FALSE;
	}
	ZeroMemory(&fds, sizeof(fds));
	fds.hFileHandle = hFile;
	fds.hMapHandle = hMap;
	fds.lpImageBase = lpImageBase;
	fds.dwInitialFileSize = dwInitialFileSize;
	fds.dwFilePathLength = strlen(pszFilePath);
	//fds.pszFullFileName = (LPSTR) malloc(fds.dwFilePathLength + 1);
	//memcpy(fds.pszFullFileName, pszFilePath, fds.dwFilePathLength + 1);//TODO????bufoverflow??
	fds.pszFullFileName = pszFilePath;
	return TRUE;
}
/*
	returns: none
	closes the whole desciptor
*/

VOID CloseFileDescriptor(FILE_DESCR& fds)
{
	UnmapViewOfFile(fds.lpImageBase);
	CloseHandle(fds.hMapHandle);
	CloseHandle(fds.hFileHandle);
	//free(fds.pszFullFileName);
	
}
/*
	returns: none
	creates read-write access descriptor
*/
VOID CreateReadWriteAccessDescr(ACCESS_DESCR& acds)
{
	ZeroMemory(&acds, sizeof(acds));
	acds.dwFileHandleAccess = GENERIC_READ | GENERIC_WRITE;
	acds.dwMapHandleAccess = PAGE_READWRITE;
	acds.dwMemoryMapObjectAccess = FILE_MAP_READ | FILE_MAP_WRITE;
	acds.dwShareMode = 0;
}
/*	
	returns:
	number of sections in exe,
	0 if not 32 bit exe
*/
DWORD GetNumberOfSections(FILE_DESCR fds)
{
	if(!IsWin32Executable(fds)) return 0;
	PIMAGE_NT_HEADERS32 pNT = GetNTHeaders(fds);
	return pNT->FileHeader.NumberOfSections;
}
/*
	returns:
	TRUE on successful creation
	FALSE otherwise
*/
BOOL GetSelfFileDescriptor(FILE_DESCR& fds)
{
	
	ACCESS_DESCR acds;
	char buf[MAX_PATH];

	GetModuleFileNameA(NULL, buf, MAX_PATH);
	if(GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		return FALSE;
	}
	CreateReadAccessDescriptor(acds);
	return CreateFileDescriptor(buf, fds, acds);
}
/*
	returns:
	TRUE on success getting the section[idx] 
	FALSE otherwise

*/
//BOOL GetSectionContainerByIdxFromSelf(SECTION_CONTAINER& scont, DWORD idx)
//{
//	FILE_DESCR fds;
//	if	(!GetSelfFileDescriptor(fds)) return FALSE;
//	if	(idx == GetSectionContainerByIdx(scont, idx, fds)) return TRUE;
//	CloseFileDescriptor(fds);
//	return FALSE;
//}
/*
returns:
Creates non-exclusive read access
*/
VOID CreateReadAccessDescriptor(ACCESS_DESCR& acds)
{
	ZeroMemory(&acds, sizeof(acds));
	acds.dwFileHandleAccess = GENERIC_READ;
	acds.dwMapHandleAccess = PAGE_READONLY;
	acds.dwMemoryMapObjectAccess = FILE_MAP_READ;
	acds.dwShareMode = FILE_SHARE_READ;
}
