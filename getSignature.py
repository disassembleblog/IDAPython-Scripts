import idaapi, idc
'''
Author: 		Ionut Iacob
Functionality: 	Get opcodes from selected area in IDAPro
Date: 			21.04.2018
Version			1.0
'''
def GetOpcodes():
    selected = idaapi.read_selection()
    print "[+] Processing range: %x - %x" % (selected[1],selected[2])

    opcodes = []
    lastInstructionAddr = NextHead(selected[2])
    size = lastInstructionAddr-selected[1]
    for i in range(size):
        opcodes.append(GetOriginalByte(selected[1]+i))
    return opcodes

def MakeString(byteArray):
    return ''.join('{:02X}'.format(x) for x in byteArray)

opcodes = GetOpcodes()

print(MakeString(opcodes))