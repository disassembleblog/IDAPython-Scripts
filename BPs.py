'''
Author: 		Ionut Iacob
Functionality: 	Add breakpoints in IDA on the functions from the bpFuncs list.
At the end of the script, a summary is printed on the output of IDA.
Aate: 			19.12.2016
'''
from idaapi import *
import idc
import idautils

print("\n")*10

bpFuncs = ["WriteFile" ,"GetCurrentProcess", "CreateEventW", "WriteProcessMemory" , "VirtualAlloc" , "VirtualProtect" , "SetSecurityDescriptorDacl" , "ResumeThread" , "RegSetValueExA" , "Process32First" , "Process32Next" , "OpenProcessToken" , "LookupPrivilegeValueA" , "LoadResource" , "LockResource" , "GetProcAddress" , "LoadLibraryExA" , "LoadLibraryA" , "GetWindowsDirectoryA" , "GetTickCount" , "GetTempPathA" , "GetSystemTime" , "GetDriveTypeA" , "FindFirstFileA" , "FindNextFileA" , "EnumWindows" , "DeleteFileA" , "CreateToolhelp32Snapshot" , "CreateThread" , "CreateProcessA" , "CreateFileW" , "CreateFileA" , "CopyFileA"]
notFound = []	# functii negasite
objFoundFuncs = [] # lista pentru functii gasite

for bpFunc in bpFuncs:
	addr = LocByName(bpFunc) 
	if addr == BADADDR:
		notFound.append(bpFunc)
	else:
		for xref in XrefsTo(addr, 0):
			buff = GetMnem(xref.frm)
			if xref.type in (16,17):	#Code_Near_Call
				objFoundFuncs.append(xref)
				#print("{} {} from, {:08X} to {:08X}".format(xref.type, XrefTypeName(xref.type), xref.frm, xref.to))

for objFoundFunc in objFoundFuncs:
	idc.AddBpt(objFoundFunc.frm)

print("Found and set a no. of {} BPs.".format(len(objFoundFuncs)))
print("These functions where not found: {}".format(notFound))



#  XREF TYPES
#define fl_CF   16              // Call Far
#define fl_CN   17              // Call Near
#define fl_JF   18              // Jump Far
#define fl_JN   19              // Jump Near
#define fl_F    21              // Ordinary flow