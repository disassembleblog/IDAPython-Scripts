'''
Author: 		Ionut Iacob
Functionality: 	Add breakpoints in IDA on the functions from the bpFuncs list.
At the end of the script, a summary is printed on the output of IDA.
Date: 			20.1.2017
Version			0.22
to to:	bp "call eax", call to a function with an abnormal ret or jmp (red)
'''
from idaapi import *
import idc
import idautils

print("\n")*10

# pentru a evita duplicate de genul CreateProcessW si CreateProcessA, ar trebui parsat tabela de IAT si daca de acolo se potriveste CreateProcess pe tabela, breakpoint
bpFuncs = ["WriteFile" ,"GetCurrentProcess", "CreateEventW", "WriteProcessMemory" , "VirtualAlloc" , "VirtualProtect" , "SetSecurityDescriptorDacl" , "ResumeThread" , "RegSetValueExA" , "Process32First" , "Process32Next" , "OpenProcessToken" , "LookupPrivilegeValueA" , "LoadResource" , "LockResource" , "GetProcAddress" , "LoadLibraryExA" , "LoadLibraryA" , "GetWindowsDirectoryA" , "GetTickCount" , "GetTempPathA" , "GetSystemTime" , "GetDriveTypeA" , "FindFirstFileA" , "FindNextFileA" , "EnumWindows" , "DeleteFileA" , "CreateToolhelp32Snapshot" , "CreateThread" , "CreateProcessA" ,"CreateProcessInternalW" ,"CreateProcessW" , "CreateFileW" , "CreateFileA" , "CopyFileA", "AdjustTokenPrivileges", "LookupPrivilegeValueW", "RegDeleteKeyExW", "OpenClipboard", "SetClipboardData", "InternetCrackUrl", "InternetConnect", "HttpOpenRequest", "HttpSendRequest", "InternetReadFile", "InternetOpen", "WSAStartup", "socket", "bind", "listen", "accept", "recv", "shutdown", "getaddrinfo", "connect", "send", "ShellExecuteExW", "CryptDecrypt", "CryptEncrypt", "CryptAcquireContextW" ,"CryptImportKey"]
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