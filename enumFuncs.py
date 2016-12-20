'''
The same thing as enumFunc.c, but in Phyton
'''
funcs = Functions()
for f in funcs:
	name = Name(f)
	end = GetFunctionAttr(f, FUNCATTR_END)
	locals = GetFunctionAttr(f, FUNCATTR_FRSIZE)
	frame = GetFrame(f) # retrieve a handle to the function’s stack frame
	if frame is None: continue
	ret = GetMemberOffset(frame, " r") # " r" is the name of the return address
	if ret == -1: continue
	firstArg = ret + 4
	args = GetStrucSize(frame) - firstArg
	Message("Function: %s, starts at %x, ends at %x\n" % (name, f, end))
	Message(" Local variable area is %d bytes\n" % locals)
	Message(" Arguments occupy %d bytes (%d args)\n" % (args, args / 4))