/*
iterate across all of the cross-references to (as opposed to from in the 
preceding example) a particular symbol:
IDA PRO BOOK 15-4
*/
#include <idc.idc>
static list_callers(bad_func) {
	auto func, addr, xref, source;
	func = LocByName(bad_func);
	if (func == BADADDR) {
		Warning("Sorry, %s not found in database", bad_func);
	}
	else {
		for (addr = RfirstB(func); addr != BADADDR; addr = RnextB(func, addr)) {
			xref = XrefType();
			if (xref == fl_CN || xref == fl_CF) {
				source = GetFunctionName(addr);
				Message("%s is called from 0x%x in %s\n", bad_func, addr, source);
			}
		}
	}
}
static main() {
	list_callers("_strcpy");
	list_callers("_sprintf");
}