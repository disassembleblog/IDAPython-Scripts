'''
Author: 		Ionut Iacob
Functionality: 	Add breakpoints in IDA on the functions from the bpFuncs list.
At the end of the script, a summary is printed on the output of IDA.
Date: 			20.12.2016
Version			0.2
'''
from idaapi import *
import idc
import idautils

print("\n")*10

# pentru a evita duplicate de genul CreateProcessW si CreateProcessA, ar trebui parsat tabela de IAT si daca de acolo se potriveste CreateProcess pe tabela, breakpoint
bpFuncs = ["WriteFile" ,"GetCurrentProcess", "CreateEventW", "WriteProcessMemory" , "VirtualAlloc" , "VirtualProtect" , "SetSecurityDescriptorDacl" , "ResumeThread" , "RegSetValueExA" , "Process32First" , "Process32Next" , "OpenProcessToken" , "LookupPrivilegeValueA" , "LoadResource" , "LockResource" , "GetProcAddress" , "LoadLibraryExA" , "LoadLibraryA" , "GetWindowsDirectoryA" , "GetTickCount" , "GetTempPathA" , "GetSystemTime" , "GetDriveTypeA" , "FindFirstFileA" , "FindNextFileA" , "EnumWindows" , "DeleteFileA" , "CreateToolhelp32Snapshot" , "CreateThread" , "CreateProcessA" ,"CreateProcessInternalW" ,"CreateProcessW" , "CreateFileW" , "CreateFileA" , "CopyFileA", "AdjustTokenPrivileges", "LookupPrivilegeValueW", "RegDeleteKeyExW", "OpenClipboard", "SetClipboardData", "InternetCrackUrl", "InternetConnect", "HttpOpenRequest", "HttpSendRequest", "InternetReadFile", "InternetOpen", "WSAStartup", "socket", "bind", "listen", "accept", "recv", "shutdown", "getaddrinfo", "connect", "send", "ShellExecute", "gethostbyname"]
notFound = []	# functii negasite
objFoundFuncs = [] # lista pentru functii gasite

for bpFunc in bpFuncs:
	addr = LocByName(bpFunc) 
	if addr == BADADDR:
		notFound.append(bpFunc)
	else:
		if len(list(XrefsTo(addr,0)))==0:
			notFound.append(bpFunc)
		for xref in XrefsTo(addr, 0):
			buff = GetMnem(xref.frm)
			if xref.type in (16,17):	#Code_Near_Call
				objFoundFuncs.append(xref)
				#print("{} {} from, {:08X} to {:08X}".format(xref.type, XrefTypeName(xref.type), xref.frm, xref.to))

for objFoundFunc in objFoundFuncs:
	idc.AddBpt(objFoundFunc.frm)

print("Found and set a no. of {} BPs.".format(len(objFoundFuncs)))
print("These functions where not found: {}/{} -> {}".format(len(notFound),len(bpFuncs),notFound))



#  XREF TYPES
#define fl_CF   16              // Call Far
#define fl_CN   17              // Call Near
#define fl_JF   18              // Jump Far
#define fl_JN   19              // Jump Near
#define fl_F    21              // Ordinary flow