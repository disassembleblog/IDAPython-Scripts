import idaapi, idc, idautils
'''
Author: 		Ionut Iacob
Functionality: 	Search for x86 instructions used in detecting VMWare	see: https://www.trapkit.de/tools/scoopyng/index.html
Date: 			21.04.2018
Version			1.0
'''
heads = Heads(SegStart(ScreenEA()),SegEnd(ScreenEA()))

antiVMAddr = []

for i in heads:
	mnem = GetMnem(i)
	vmchecks = ['sidt','sgdt','sldt','smsw','str','in','cpuid']
	if mnem in vmchecks:
		antiVMAddr.append(i)

if(len(antiVMAddr)):
	print("Several AntiVM tricks may be implemented in binary. Check the following {} addresses".format(len(antiVMAddr)))
	for i in antiVMAddr:
		print('0x{:08X} : {}'.format(i,GetDisasm(i)))
		SetColor(i,CIC_ITEM, 0xefaf5b)



print('checkVM: FIN')