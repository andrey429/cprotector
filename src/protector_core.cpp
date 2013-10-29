#include "protector_core.h"
#include <imagehlp.h>

/* algo:
getsection from self
addsection to tgt - DO NOT CLOSE TGT

getsection from tgt
changeEP in tgt
createprotenv from tgt

prot_env->update oep

modifysection in tgt
write section

*/
BOOL ProtectFile(LPSTR pszFile)
{
	DWORD dwNumOfScns, dwLastScnIdx, dwOEP, dwCounter;
	FILE_DESCR tgt_fds, self_fds;
	ACCESS_DESCR tgt_acds;//, self_acds;
	PROTECTION_ENVIRONMENT prenv;
	SECTION_CONTAINER scont;

	//CreateReadAccessDescriptor(self_acds);
	CreateReadWriteAccessDescr(tgt_acds);
	GetSelfFileDescriptor(self_fds);
	CreateFileDescriptor(pszFile,tgt_fds,tgt_acds);
	
	if	(!(dwNumOfScns = GetNumberOfSections(self_fds)))
	{
		CloseFileDescriptor(self_fds);
		CloseFileDescriptor(tgt_fds);
		return FALSE;
	}
	dwLastScnIdx = dwNumOfScns - 1;
	if	(GetSectionContainerByIdx(scont, dwLastScnIdx, self_fds) == DWORD(-1))
	{
		CloseFileDescriptor(self_fds);
		CloseFileDescriptor(tgt_fds);
		return FALSE;
	}

	if(!AddNewSection(tgt_fds, scont, ".protect", MEM_EXEC_READ_WRITE_CODE))
	{
		CloseFileDescriptor(self_fds);
		CloseFileDescriptor(tgt_fds);
		return FALSE;
	}
	
	if(!(dwNumOfScns = GetNumberOfSections(tgt_fds)))
	{
		CloseFileDescriptor(self_fds);
		CloseFileDescriptor(tgt_fds);
		return FALSE;
	}
	dwLastScnIdx = dwNumOfScns - 1;
	if(GetSectionContainerByIdx(scont, dwLastScnIdx, tgt_fds) == DWORD(-1))
	{
		CloseFileDescriptor(self_fds);
		CloseFileDescriptor(tgt_fds);
		return FALSE;
	}
	
	ChangeEntryPoint(tgt_fds, scont.scnHeader.VirtualAddress, dwOEP);
	
	if(!CreateProtectionEnvironment(tgt_fds, prenv))
	{
		CloseFileDescriptor(self_fds);
		CloseFileDescriptor(tgt_fds);
		return FALSE;
	}
	prenv.dwOEP = dwOEP;

	if(!ModifyProtectionSection(scont, prenv))
	{
		CloseFileDescriptor(self_fds);
		CloseFileDescriptor(tgt_fds);
		return FALSE;
	}
	SetFilePointer(tgt_fds.hFileHandle, scont.scnHeader.PointerToRawData, NULL, FILE_BEGIN);
	if(!WriteFile(tgt_fds.hFileHandle, scont.pScnRawData, 
		scont.scnHeader.SizeOfRawData, &dwCounter, NULL))
	{
		CloseFileDescriptor(self_fds);
		CloseFileDescriptor(tgt_fds);
		return FALSE;
	}
	CloseFileDescriptor(tgt_fds);
	CloseFileDescriptor(self_fds);
	return TRUE;

}
/*BOOL ProtectFile(LPSTR pszFile)
{
	DWORD dwNumberOfSections;
	FILE_DESCR selffd, targetfd;
	SECTION_CONTAINER scont;
	ACCESS_DESCR acds;
	PROTECTION_ENVIRONMENT prenv;

	//if(!GetSelfFileDescriptor(selffd)) return FALSE;
	ACCESS_DESCR ad;
	CreateReadAccessDescriptor(ad);
	CreateFileDescriptor("C:\\masm32\\protector.exe", selffd, ad);
	dwNumberOfSections = GetNumberOfSections(selffd);
	DWORD dwLastScnIdx = dwNumberOfSections - 1;
	if(dwLastScnIdx != GetSectionContainerByIdx(scont, dwLastScnIdx, selffd))
	{
		return FALSE;
	}
	CreateReadWriteAccessDescr(acds);
	if(!CreateFileDescriptor(pszFile, targetfd, acds)) return FALSE;

	if(!AddNewSection(targetfd, scont, ".protect", MEM_EXEC_READ_WRITE_CODE)) return FALSE;//^|
	CloseFileDescriptor(selffd);
	
	
	dwNumberOfSections = GetNumberOfSections(targetfd);
	dwLastScnIdx = dwNumberOfSections - 1;
	GetSectionContainerByIdx(scont, dwLastScnIdx, targetfd);
	DWORD dwTempOEP;
	ChangeEntryPoint(targetfd, scont.scnHeader.VirtualAddress, dwTempOEP);
	if(!CreateProtectionEnvironment(targetfd, prenv)) return FALSE;
	DWORD dwTemp = 0;
	//PIMAGE_NT_HEADERS32 pNTRes = GetNTHeaders(targetfd);
	//prenv.dwOEP = pNTRes->OptionalHeader.AddressOfEntryPoint;
	prenv.dwOEP = dwTempOEP;
	if(!ModifyProtectionSection(scont, prenv)) return FALSE;
	SetFilePointer(targetfd.hFileHandle, scont.scnHeader.PointerToRawData, 0, FILE_BEGIN);
	if(!WriteFile(targetfd.hFileHandle, scont.pScnRawData, scont.scnHeader.SizeOfRawData,
		&dwTemp, NULL))
	{
		return FALSE;
	}
	

	CloseFileDescriptor(targetfd);
	
	return TRUE;
}*/
/*
	returns:
	TRUE on success, protection environment in prenv
	FALSE on failure
*/
BOOL CreateProtectionEnvironment(FILE_DESCR fds, PROTECTION_ENVIRONMENT& prenv)
{
	DWORD dwOldChksum, dwNewChksum;
	PIMAGE_NT_HEADERS32 pNTRes;
	ZeroMemory(&prenv, sizeof(prenv));

	prenv.dwFileAttributes = GetFileAttributesA(fds.pszFullFileName);
	prenv.dwMapSize = fds.dwInitialFileSize;
	prenv.pszFilePath = fds.pszFullFileName;
	
	pNTRes = CheckSumMappedFile(fds.lpImageBase, fds.dwInitialFileSize, 
		&dwOldChksum, &dwNewChksum);
	
	if	(pNTRes->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}
	prenv.dwFileChecksum = dwNewChksum;
	return TRUE;
}
DWORD SearchForSignature(PBYTE pRawData, DWORD dwRawDataSize, DWORD dwSignature)
{
	DWORD dwPos = 0;
	while((dwPos < dwRawDataSize) && memcmp((PBYTE)((DWORD)pRawData + dwPos), &dwSignature, 4))
	{	
		dwPos++;
	}
	return dwPos < dwRawDataSize ? dwPos : DWORD(-1);
}
BOOL ModifyProtectionSection(SECTION_CONTAINER& scont, PROTECTION_ENVIRONMENT penv)
{
	PBYTE pScnRawData = scont.pScnRawData;
	DWORD dwProtDataOffset = SearchForSignature(pScnRawData, scont.scnHeader.SizeOfRawData, 0xbadceed);
	if	(dwProtDataOffset == DWORD(-1)) return FALSE;
	
	memcpy((PBYTE)((DWORD)pScnRawData + dwProtDataOffset), &penv.dwMapSize, 4);
	dwProtDataOffset +=4;
	memcpy((PBYTE)((DWORD)pScnRawData + dwProtDataOffset), &penv.dwOEP, 4);
	dwProtDataOffset +=4;
	memcpy((PBYTE)((DWORD)pScnRawData + dwProtDataOffset), &penv.dwFileAttributes, 4);
	dwProtDataOffset +=4;
	memcpy((PBYTE)((DWORD)pScnRawData + dwProtDataOffset), &penv.dwFileChecksum, 4);
	dwProtDataOffset +=4;
	//
	memcpy((PBYTE)((DWORD)pScnRawData + dwProtDataOffset), &scont.scnHeader.VirtualAddress, 4);
	dwProtDataOffset +=4;
	//
	memcpy((PBYTE)((DWORD)pScnRawData + dwProtDataOffset), penv.pszFilePath, strlen(penv.pszFilePath));
	
	return TRUE;
}