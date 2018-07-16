'''
Display all XORs inside a IDB to rapidly identify encryption routines
'''
from idaapi import *
funcs = Functions()
notFound = 1
for func in funcs:
	ea = func
	E = list(FuncItems(ea))
	for e in E:
		if GetMnem(e) == "xor":
			if GetOpnd(e,0) != GetOpnd(e,1):
				#print "%08X"%e, GetDisasm(e)
				print("{} {:08X} {}".format(Name(ea),e, GetDisasm(e)))
				notFound = 0
	if notFound:
		print "Niente"


