'''
Author: 		Ionut Iacob
Functionality: 	Add breakpoints in IDA on the functions from the bpFuncs list.
At the end of the script, a summary is printed on the output of IDA.
Date: 			20.07.2017
Version			0.92
to to:	bp "call eax", call to a function with an abnormal ret or jmp at it's end (red ending)
'''
from idaapi import *
import idc
import idautils

print("\n")*10

# pentru a evita duplicate de genul CreateProcessW si CreateProcessA, ar trebui parsat tabela de IAT si daca de acolo se potriveste CreateProcess pe tabela, breakpoint
bpFuncs = ["accept","bind","connect","CopyFileA","CopyFileW","CreateEventW","CreateFileA","CreateFileW","CreateMutexW","CreatePipe","CreateProcessA","CreateProcessInternalW","CreateProcessW","CreateServiceA","CreateThread","CreateToolhelp32Snapshot","CryptAcquireContextW","CryptCreateHash","CryptDecrypt","CryptDestroyHash","CryptDestroyKey","CryptEncrypt","CryptExportKey","CryptGenKey","CryptGetHashParam","CryptHashData","CryptImportKey","CryptImportPublicKeyInfo","CryptProtectData","DeleteFileA","DeviceIoControl","FindFirstFileA","FindFirstFileExA","FindNextFileA","getaddrinfo","GetAsyncKeyState","GetCurrentProcess","GetDriveTypeA","GetDriveTypeW","GetForegroundWindow","GetKeyState","GetProcAddress","GetSystemTime","GetTempPathA","GetTickCount","GetWindowsDirectoryA","GlobalAddAtom","GlobalGetAtomName","HttpOpenRequest","HttpSendRequest","InternetConnect","InternetCrackUrl","InternetOpen","InternetReadFile","listen","LoadLibraryA","LoadLibraryExA","LoadResource","LockResource","LookupPrivilegeValueA","LookupPrivilegeValueW","MapViewOfFile","memcpy","NtSetContextThread","OpenClipboard","OpenMutexW","OpenProcessToken","OpenSCManagerA","OpenServiceW","Process32First","Process32Next","Process32NextW","recv","RegDeleteKeyExW","RegQueryValueExA","RegSetValueExA","ResumeThread","RtlMoveMemory","send","SetClipboardData","SetEndOfFile","SetSecurityDescriptorDacl","SetThreadContext","ShellExecuteExA","ShellExecuteExW","shutdown","socket","StartServiceCtrlDispatcherA","StartServiceCtrlDispatcherW","VirtualAlloc","VirtualAllocEx","VirtualProtect","WriteFile","WriteProcessMemory","WSAStartup","AdjustTokenPrivileges","CallNextHookEx","ControlService","CreateMutexA","CreateServiceW","EnumWindows","FindFirstFileW","FindResourceW","GetThreadContext","IsDebuggerPresent","memcpy","NtResumeThread","OpenProcess","OpenServiceA","Process32FirstW","RegisterServiceCtrlHandlerA","RegQueryValueExW","RegSetValueExW","SetFilePointer","SetSecurityDescriptorDacl","SetServiceStatus","SetUnhandledExceptionFilter","SetWindowsHookExW","ShellExecuteA","TerminateProcess","UnhandledExceptionFilter","WinHttpConnect","WinHttpOpen","WinHttpOpenRequest","WinHttpSendRequest","ZwAllocateVirtualMemory", "QueueUserAPC","SuspendThread","OpenThread","Thread32First","Thread32Next","SetWindowsHookEx","FindFirstFileExW","CreateRemoteThread","CallWindowProc","CreateFiber","ConvertThreadToFiber","SwitchToFiber","FindNextFileW","FindNextFileA","FindNextFileExW","FindNextFileExA","Sleep","InternetCrackUrlA","InternetCloseHandle","InternetQueryOptionA","InternetOpenA","InternetConnectA","HttpOpenRequestA","HttpAddRequestHeadersA","HttpSendRequestA","HttpSendRequestExA","HttEndRequestA","HttpQueryInfoA","InternetReadFile","InternetWriteFile","InternetSetOptionA","","","","","","","","","","","","","","","",""]
notFound = []				# unfound functions
objFoundFuncs = []		 	# found functions

for bpFunc in bpFuncs:						# iterate through each function we want to breakpoint
	addr = LocByName(bpFunc) 				# check if the func is present in the IAT of the PE
	if addr == BADADDR:						# if no addr was found
		notFound.append(bpFunc)				# add unfound functions to list
	else:									# 
		if len(list(XrefsTo(addr,0)))==0:	# search for all xrefs to that addr, make it a list and get a list lenght
			notFound.append(bpFunc)			# if list is 0 add function to unfound list
		for xref in XrefsTo(addr, 0):		# iterate through all xrefs
			buff = GetMnem(xref.frm)		# get the mnemonic
			if xref.type in (16,17):		# check if mnem is a call
				objFoundFuncs.append(xref)	# add addr to breakpoint array
				MakeComm(xref.frm, bpFunc)	# add comment

for objFoundFunc in objFoundFuncs:
	idc.AddBpt(objFoundFunc.frm)

#print("Found and set a no. of {} BPs.".format(len(objFoundFuncs)))
#print("These functions where not found: {}/{} -> {}".format(len(notFound),len(bpFuncs),notFound))
print("Breakpoint script finished. Check breakpoint window.")


#  XREF TYPES
#define fl_CF   16              // Call Far
#define fl_CN   17              // Call Near
#define fl_JF   18              // Jump Far
#define fl_JN   19              // Jump Near
#define fl_F    21              // Ordinary flow



# atombombing code injection 
# "ZwAllocateVirtualMemory", "VirtualAlloc", "memcpy", "RtlMoveMemory", "NtSetContextThread", "GlobalAddAtom", "GlobalGetAtomName",