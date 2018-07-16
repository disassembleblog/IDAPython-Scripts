'''
Functionality: 	Display and Add comments with the decrypted strings for the following DLL: f65a4dfeef0a7b5d539ab889d8badf0100017ebe11a9cb784882813ddbf3a00c
Date: 			13.07.2018
Version			0.1
'''
import idaapi, idc, idautils, re, json

def GetString(instr):
	chars = []
	count = 0
	while(Byte(instr+count)):
		chars.append(chr(Byte(instr+count)))
		count+=1
	return "".join(chars)

def IsAddress(instr):
	pattern = re.compile("0[a-fA-F0-9]{7}")
	if not pattern.match(instr):
		return False
	return True

def DecodeString(encodedString):
	key = "5VANV4SDMC3VEAFR8S2M3M9U6WRH3P7FDD9T9Q10IAG5WZJ5K5"
	keyLen = len(key)
	encStrLen = len(encodedString)
	prevEncodedByte = 0
	encStrList = []
	keyList = []

	encodedString = [encodedString[i:i+2] for i in range(0, encStrLen, 2)]
	for byte in encodedString:
		encStrList.append(int(byte, 16))

	key = [key[i] for i in range(0, keyLen, 1)]
	for byte in key:
		keyList.append(ord(byte))

	prevEncodedByte = encStrList[0]

	encStrLen = len(encStrList)
	keyLen = len(keyList)
	keyOffset = 0

	decodedString = []
	for i in range(1,encStrLen):
		if(keyOffset>=keyLen):
			keyOffset = 0
		decodedByte = encStrList[i] ^ keyList[keyOffset]
		if(decodedByte>prevEncodedByte):
			decodedByte -= prevEncodedByte
		else:
			decodedByte = decodedByte + 0xFF - prevEncodedByte
		prevEncodedByte = encStrList[i]
		decodedString.append(chr(decodedByte))
		
		keyOffset += 1

	return("".join(decodedString))
# ===========================================================================
# ===========================================================================
funcName = LocByName('fDecryption')
funcXrefs = CodeRefsTo(funcName,1)
strings = []

for xref in funcXrefs:
	intructs = 0
	tempInstr = xref
	while(intructs==0):
		tempInstr = PrevHead(tempInstr,SegStart(tempInstr))
		mnem = GetMnem(tempInstr)
		if(mnem == 'mov'):
			intructs = tempInstr

	encodedStrAddr = GetOperandValue(intructs,1)

	if(IsAddress("{:08X}".format(encodedStrAddr))):
		encodedStr = GetString(encodedStrAddr)
		decodedStr = DecodeString(encodedStr)
		print('CALL @ {:08X} with \"{}\" -> \"{}\"'.format(xref,encodedStr,decodedStr))
		MakeComm(xref,''.join(decodedStr))

print("FIN")

