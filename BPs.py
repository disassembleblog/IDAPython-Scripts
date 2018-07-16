'''
Functionality: 	Add breakpoints in IDA on the functions from the bpFuncs list.
At the end of the script, a summary is printed on the output of IDA.
Date: 			24.05.2018
Version			2.1
'''
import idaapi
import idc
import idautils

print("\n")*10
print('=')*100
def GetImports():
    print('Fetching IAT entries.')
    IAT = []
    
    for i in range(idaapi.get_import_module_qty()):
        dllname = idaapi.get_import_module_name(i)
        if not dllname:
            continue

        entries = []
        def cb(ea, name, ordinal):
            entries.append((ea, name, ordinal))
            return True  

        idaapi.enum_import_names(i, cb)

        for ea, name, ordinal in entries:
            IAT.append(name)

    return IAT

def AddBreakpoint(iatList, breakList):

    def GetProcAddressAPIString(eipaddr):
        instr = PrevHead(eipaddr,SegStart(eipaddr))
    
        pushes = []

        while(len(pushes)<2):
            if(GetMnem(instr)=='push'):
                pushes.append(instr)
            instr = PrevHead(instr,SegStart(eipaddr))


        encodedStr = GetOperandValue(pushes[1],0)
        print("Arg @ {:08X} points to: {}".format(instr,GetString(encodedStr)))
        
        return GetString(encodedStr)

    def IsBreakItemInIAT(breakItem,iatList):
        for iatItemName in iatList:
            if breakItem in iatItemName:
                return iatItemName
        return 0

    def GetAPIListToAddBreakpointOn(breakList):
        toBreakOnList = []
        for breakItem in breakList:
            breakOnAPIName = IsBreakItemInIAT(breakItem,iatList)
            if breakOnAPIName:
                #print('We should break on {}'.format(breakOnAPIName))
                toBreakOnList.append(breakOnAPIName)
        return toBreakOnList

    def Breakpoint(apiBreakList):
        for apiName in apiBreakList:
            addr = LocByName(apiName)
            if addr != BADADDR:
                xrefs = list(XrefsTo(addr,0))
                if len(xrefs):
                    for xref in xrefs:
                        if xref.type in (16,17):
                            idc.AddBpt(xref.frm)
                            MakeComm(xref.frm,apiName)
                            if(apiName == 'GetProcAddress'):
                                resolveName = GetProcAddressAPIString(xref.frm)
                                MakeComm(xref.frm,"{}({})".format(apiName,resolveName))
        return 0

    print('Adding breakpoints.')

    return Breakpoint(GetAPIListToAddBreakpointOn(breakList))



bpFuncs = ['accept','bind','connect','CopyFile','CreateEvent','CreateFile','CreateMutex','CreatePipe','CreateProcess','CreateProcessInternal','CreateService','CreateThread','CreateToolhelp32Snapshot','CryptAcquireContext','CryptCreateHash','CryptDecrypt','CryptDestroyHash','CryptDestroyKey','CryptEncrypt','CryptExportKey','CryptGenKey','CryptGetHashParam','CryptHashData','CryptImportKey','CryptImportPublicKeyInfo','CryptProtectData','DeleteFile','DeviceIoControl','FindFirstFile','FindNextFile','getaddrinfo','GetAsyncKeyState','GetCurrentProcess','GetDriveType','GetForegroundWindow','GetKeyState','GetProcAddress','GetSystemTime','GetTempPath','GetTickCount','GetWindowsDirectory','GlobalAddAtom','GlobalGetAtomName','HttpOpenRequest','HttpSendRequest','InternetConnect','InternetCrackUrl','InternetOpen','InternetReadFile','listen','LoadLibrary','LoadResource','LockResource','LookupPrivilegeValue','MapViewOfFile','memcpy','NtSetContextThread','OpenClipboard','OpenMutex','OpenProcessToken','OpenSCManager','OpenService','Process32First','Process32Next','recv','RegDeleteKey','RegQueryValue','RegSetValue','ResumeThread','RtlMoveMemory','send','SetClipboardData','SetEndOfFile','SetSecurityDescriptorDacl','SetThreadContext','ShellExecute','shutdown','socket','StartServiceCtrlDispatcher','VirtualAlloc','VirtualProtect','WriteFile','WriteProcessMemory','WSAStartup','AdjustTokenPrivileges','CallNextHook','ControlService','EnumWindows','FindResource','GetThreadContext','IsDebuggerPresent','NtResumeThread','OpenProcess','RegisterServiceCtrlHandler','SetFilePointer','SetServiceStatus','SetUnhandledExceptionFilter','SetWindowsHook','TerminateProcess','UnhandledExceptionFilter','WinHttpConnect','WinHttpOpen','WinHttpOpenRequest','WinHttpSendRequest','ZwAllocateVirtualMemory','QueueUserAPC','SuspendThread','OpenThread','Thread32First','Thread32Next','CreateRemoteThread','CallWindowProc','CreateFiber','ConvertThreadToFiber','SwitchToFiber','Sleep','InternetCloseHandle','InternetQueryOption','HttpAddRequestHeaders','HttEndRequest','HttpQueryInfo','InternetWriteFile','InternetSetOption','RtlDecompressBuffer','HeapCreate']


AddBreakpoint(GetImports(),bpFuncs)

print("Breakpoint script finished. Check breakpoint window. CTRL+ALT+B")
print('=')*100

#  XREF TYPES
#define fl_CF   16              // Call Far
#define fl_CN   17              // Call Near
#define fl_JF   18              // Jump Far
#define fl_JN   19              // Jump Near
#define fl_F    21              // Ordinary flow