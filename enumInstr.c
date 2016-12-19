/*
counts the number of instructions contained in the function identi-
fied by the current cursor position
IDA PRO BOOK 15.2
*/

#include <idc.idc>
static main() {
	auto func, end, count, inst;
	func = GetFunctionAttr(ScreenEA(), FUNCATTR_START);
	if (func != -1) {
		end = GetFunctionAttr(func, FUNCATTR_END);
		count = 0;
		inst = func;
		while (inst < end) {
			count++;
			inst = FindCode(inst, SEARCH_DOWN | SEARCH_NEXT);
		}
		Warning("%s contains %d instructions\n", Name(func), count);
	}
	else {
		Warning("No function found at location %x", ScreenEA());
	}
}