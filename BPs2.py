from idaapi import *
import idc
import idautils

bpFuncs = ["WriteFile" , "WriteProcessMemory" , "VirtualAlloc" , "VirtualProtect" , "SetSecurityDescriptorDacl" , "ResumeThread" , "RegSetValueExA" , "Process32First" , "Process32Next" , "OpenProcessToken" , "LookupPrivilegeValueA" , "LoadResource" , "LockResource" , "GetProcAddress" , "LoadLibraryExA" , "LoadLibraryA" , "GetWindowsDirectoryA" , "GetTickCount" , "GetTempPathA" , "GetSystemTime" , "GetDriveTypeA" , "FindFirstFileA" , "FindNextFileA" , "EnumWindows" , "DeleteFileA" , "CreateToolhelp32Snapshot" , "CreateThread" , "CreateProcessA" , "CreateFileW" , "CreateFileA" , "CopyFileA"]

#search for all Calls within the disassembly
allinstrs = Functions()  # 660 elemente
allInstrList = []
allinstrsDict = {}
x = 5;
for func in allinstrs:
	allInstrList = list(FuncItems(func)) #addrese
	for instr in allInstrList:
		temp = GetOpnd(instr,0)
		if GetMnem(instr)=="call":
			if temp.find("GetProcAddress") != -1:
				print("{:08X} , {}".format(instr,GetDisasm(instr)))
			#populate a dictionary with Address and Called Funcion
			#allinstrsDict.update({instr:GetOpnd(instr,0)})
			#print("{:08X} -> {}".format(instr,GetOpnd(instr,0)))
			# temp = GetOpnd(instr,0)
			# if temp.find("GetProcAddres") != -1:
			# 	print "found"
'''
file = open("C:\\Users\\IonutI\\Desktop\\test.txt",'w')
#iterate through each bpFuncs and check if in dictionary, then breakpoint
for key, value in allinstrsDict.iteritems():
	#print key,value
	file.write(str(key))
	file.write(",")
	file.write(value)
	file.write("\n")
	for bpFunc in bpFuncs:
		if value.find(bpFunc) != -1:
			print("{:08X} {}".format(key,GetDisasm(key)))
		# 	idc.AddBpt(key)
		# 	file.write(GetDisasm(key))
		# 	file.write("\n")
file.close()
print "Finish"