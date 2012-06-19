#include <stdio.h>
#include <windows.h>

unsigned char sc[] = {
    0x9a, 0x00, 0x00, 0x00, 0x00, 0x33, 0x00,
    0xc3,
    0xcb,
};

int main()
{
    DWORD old;
    VirtualProtect(sc, sizeof(sc), PAGE_EXECUTE_READWRITE, &old);

    *(unsigned long *)(sc + 1) = (unsigned long)(sc + 8);
    ((void(*)()) sc)();
}
