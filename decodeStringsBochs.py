'''
Functionality: 	Decrypt strings inside an IDB by emulating the executable inside Bochs.
Date: 			05.02.2018
Version			0.2
Details: 

create a proper function type and name in you IDB
set the "fDecodeString1" to you function name at lines: -15- and -50-
Ex: int ___cdecl decode1 (char*, char*, int)
then enable bochs debugger, check "stop on start" and have it set to "IDB" instead of "PE" debugging
ready to go! 
'''

import idaapi
import idc
import idautils

#get address of the decoding function
poiFunc = LocByName('fDecodeString1')

if not poiFunc:
	exit("KKT")
#get all refeerences to that function
xrefsDec1 = CodeRefsTo(poiFunc,1)

#iterate though each reference
for xref in xrefsDec1:

	def GetStrLen(instr):
		count = 0
		while(Byte(instr+count)):
			count += 1
		return count

	pushes = []
	instr = PrevHead(xref,SegStart(xref))
	
	while(len(pushes)<3):
		if(GetMnem(instr)=='push'):
			pushes.append(instr)
		instr = PrevHead(instr,SegStart(xref))

	if(len(pushes)!=3):
		print("ERROR BOSS")

	encodedStr = GetOperandValue(pushes[0],0)
	encodedLen = GetOperandValue(pushes[2],0)
	print('Decoding string {:08X}'.format(pushes[0]))
	if(encodedLen==0):
		try:
			#print('No len for string from addr {:08X}'.format(pushes[0]))
			encodedLen = GetStrLen(encodedStr)
		except:
			encodedLen = AskLong(0,'Lenght of {:08X}'.format(encodedStr))
			if(encodedLen<=0):
				print('Skipping {:08X}'.format(encodedStr))
				continue

	decodedStr = Appcall.buffer(" ",encodedLen)

	
	Appcall.fDecodeString1(encodedStr,decodedStr,encodedLen)
	MakeComm(xref,decodedStr.value)
	print(decodedStr.value)
print('FIN')