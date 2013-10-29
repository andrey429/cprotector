#include <windows.h>
#include <commdlg.h>
#include "pe_commons.h"
#include "protector_core.h"

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR lpCmdLine, int nShowCmd)
{
	char szPathName[MAX_PATH];
	OPENFILENAMEA ofn;
	ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.lpstrFile = szPathName;
	ofn.lpstrFile[0] = '\0';
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrFilter = "Win32 executable files\0*.exe\0\0";
	ofn.nFilterIndex = 1;
	ofn.lpstrTitle = "Choose a file to protect";
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
	int key_pressed = MessageBoxA(NULL, "CProtector - protector for executables\nWould you like to choose a file to protect?",
		"CProtector", MB_OKCANCEL | MB_ICONQUESTION);
	if	(key_pressed == IDCANCEL)
	{
		ExitProcess(0);
	}
	if(!GetOpenFileNameA(&ofn)) ExitProcess(0);
	if(!ProtectFile(ofn.lpstrFile))
	{
		MessageBoxA(NULL, "Error occured : file is busy or error unknown","CProtector", MB_ICONERROR);
	} else
	{
		MessageBoxA(NULL, "Protection installed","CProtector", MB_ICONINFORMATION);
	}
	
	ExitProcess(0);

}