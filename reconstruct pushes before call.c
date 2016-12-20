/*
Here we have a situation where a script might be able to restore some of
the information that we are accustomed to seeing in our disassemblies. List-
ing 15-6 is a first effort at automatically recognizing instructions that are set-
ting up parameters for function calls:
*/
#include <idc.idc>
static main() {
  auto addr, op, end, idx;
  auto func_flags, type, val, search;
  search = SEARCH_DOWN | SEARCH_NEXT;
  addr = GetFunctionAttr(ScreenEA(), FUNCATTR_START);
  func_flags = GetFunctionFlags(addr);
  if (func_flags & FUNC_FRAME) { //Is this an ebp-based frame?
    end = GetFunctionAttr(addr, FUNCATTR_END);
    for (; addr < end && addr != BADADDR; addr = FindCode(addr, search)) {
      type = GetOpType(addr, 0);
      if (type == 3) { //Is this a register indirect operand?
        if (GetOperandValue(addr, 0) == 4) { //Is the register esp?
          MakeComm(addr, "arg_0"); //[esp] equates to arg_0
        }
      }
      else if (type == 4) { //Is this a register + displacement operand?
        idx = strstr(GetOpnd(addr, 0), "[esp"); //Is the register esp?
        if (idx != -1) {
          val = GetOperandValue(addr, 0); //get the displacement
          MakeComm(addr, form("arg_%d", val)); //add a comment
        }
      }
    }
  }
}
