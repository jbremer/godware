#include <stdio.h>
#include <windows.h>

unsigned char sc[] = {
    0xea, 0x00, 0x00, 0x00, 0x00, 0x23, 0x00,
    0xc3,
};

int main()
{
    DWORD old;
    VirtualProtect(sc, sizeof(sc), PAGE_EXECUTE_READWRITE, &old);

    *(unsigned long *)(sc + 1) = (unsigned long)(sc + 7);
    ((void(*)()) sc)();
}
