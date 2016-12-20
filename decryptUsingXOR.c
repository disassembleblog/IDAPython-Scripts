/*
this script simply XORs a stream of data from memory and patches the bytes in IDA PRO
*/
auto var_4, addr;
auto lenght = 0x3C1;
bytesAddr = 0x804B880;

for (var_4 = 0; var_4 <= lenght; var_4++) {
addr = bytesAddr + var_4;
PatchByte(addr, Byte(addr) ^ 0x4B);
}