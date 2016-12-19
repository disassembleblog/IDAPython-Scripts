/*
we derive the list of all function calls made within a function by iterating
through each instruction in the function to determine if the instruction calls
another function.
IDA PRO BOOK 15.3
*/

#include <idc.idc>
static main() {
	auto func, end, target, inst, name, flags, xref;
	flags = SEARCH_DOWN | SEARCH_NEXT;
	func = GetFunctionAttr(ScreenEA(), FUNCATTR_START);
	if (func != -1) {
		name = Name(func);
		end = GetFunctionAttr(func, FUNCATTR_END);
		for (inst = func; inst < end; inst = FindCode(inst, flags)) {
			for (target = Rfirst(inst); target != BADADDR; target = Rnext(inst, target)) {
				xref = XrefType();
				if (xref == fl_CN || xref == fl_CF) {
					Message("%s calls %s from 0x%x\n", name, Name(target), inst);
				}
			}
		}
	}
	else {
		Warning("No function found at location %x", ScreenEA());
	}
}