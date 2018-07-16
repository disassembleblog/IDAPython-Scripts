'''
Functionality: 	Decrypt strings inside an IDB by statically reversing the executable.
Date: 			05.02.2018
Version			0.2
Details: 		Rename the function name at line 10;
'''

import idaapi, idc, idautils
# Decryption function must be reversed and written in python
funcName = LocByName('fDecodeString1')

funcXrefs = CodeRefsTo(funcName,1)

for xref in funcXrefs:
	print("Function referenced from address: {:08X}".format(xref))

	def GetStrLen(instr):
		count = 0
		while(Byte(instr+count)):
			count += 1
		return count


	prevInstr = []
	while(len(prevInstr)==0):
		temp = PrevHead(xref,SegStart(xref))
		if(GetMnem(temp)=='push'):
			prevInstr.append(temp)
			continue
		temp = PrevHead(temp,SegStart(xref))

	prevInstr = prevInstr[0]

	try:
		encodedStr = GetOperandValue(prevInstr,0)
		encodedLen = GetStrLen(encodedStr)
	except:
		print('Can\'t get string from address: {:08X}'.format(prevInstr))
		Jump(encodedStr)
		encodedLen = AskLong(0,'String lenght @ {:08X}'.format(encodedStr))
		if(encodedLen==0):
			print('No lenght given, skipping string.')

	#print('String: {:08X} @ {}'.format(encodedStr,encodedLen))
	encBytes = []
	for iter in range(encodedLen):
		#print("0x{:02X}".format(Byte(encodedStr+iter)))
		encBytes.append(Byte(encodedStr+iter))

	decBytes = []

	for byte in encBytes:
		buff = byte ^ 0x41
		buff -= 10
		decBytes.append(chr(buff))

	print(''.join(decBytes))
	MakeComm(xref,''.join(decBytes))

