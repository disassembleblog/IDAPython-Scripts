/*
iterates through every function in a database and prints basic
information about each function, including the start and end addresses of
the function, the size of the function’s arguments, and the size of the func-
tion’s local variables. All output is sent to the output window.
IDA PRO BOOK 15.1
*/

#include <idc.idc>
static main() {
	auto addr, end, args, locals, frame, firstArg, name, ret;
	addr = 0;
	for (addr = NextFunction(addr); addr != BADADDR; addr = NextFunction(addr)) {
		name = Name(addr);
		end = GetFunctionAttr(addr, FUNCATTR_END);
		locals = GetFunctionAttr(addr, FUNCATTR_FRSIZE);
	frame = GetFrame(addr); // retrieve a handle to the function’s stack frame
	ret = GetMemberOffset(frame, " r"); // " r" is the name of the return address
	if (ret == -1) continue;
	firstArg = ret + 4;
	args = GetStrucSize(frame) - firstArg;

	Message("Function: %s, starts at %x, ends at %x\n", name, addr, end);
	Message(" Local variable area is %d bytes\n", locals);
	Message(" Arguments occupy %d bytes (%d args)\n", args, args / 4);
	}
}