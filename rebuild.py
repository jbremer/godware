import sys, struct
from ctypes import *

class IMAGE_DOS_HEADER(Structure):
    _fields_ = [
        ('e_magic', c_ushort),
        ('e_cblp', c_ushort),
        ('e_cp', c_ushort),
        ('e_crlc', c_ushort),
        ('e_cparhdr', c_ushort),
        ('e_minalloc', c_ushort),
        ('e_maxalloc', c_ushort),
        ('e_ss', c_ushort),
        ('e_sp', c_ushort),
        ('e_csum', c_ushort),
        ('e_ip', c_ushort),
        ('e_cs', c_ushort),
        ('e_lfarlc', c_ushort),
        ('e_ovno', c_ushort),
        ('e_res1', c_ushort * 4),
        ('e_oemid', c_ushort),
        ('e_oeminfo', c_ushort),
        ('e_res2', c_ushort * 10),
        ('e_lfanew', c_long)
    ]

class IMAGE_FILE_HEADER(Structure):
    _fields_ = [
        ('Machine', c_ushort),
        ('NumberOfSections', c_ushort),
        ('TimeDateStamp', c_uint),
        ('PointerToSymbolTable', c_uint),
        ('NumberOfSymbols', c_uint),
        ('SizeOfOptionalHeader', c_ushort),
        ('Characteristics', c_ushort)
    ]

class IMAGE_DATA_DIRECTORY(Structure):
    _fields_ = [
        ('VirtualAddress', c_uint),
        ('Size', c_uint)
    ]

class IMAGE_OPTIONAL_HEADER(Structure):
    _fields_ = [
        ('Magic', c_ushort),
        ('MajorLinkerVersion', c_ubyte),
        ('MinorLinkerVersion', c_ubyte),
        ('SizeOfCode', c_uint),
        ('SizeOfInitializedData', c_uint),
        ('SizeOfUninitializedData', c_uint),
        ('AddressOfEntryPoint', c_uint),
        ('BaseOfCode', c_uint),
        ('BaseOfData', c_uint),
        ('ImageBase', c_uint),
        ('SectionAlignment', c_uint),
        ('FileAlignment', c_uint),
        ('MajorOperatingSystemVersion', c_short),
        ('MinorOperatingSystemVersion', c_short),
        ('MajorImageVersion', c_short),
        ('MinorImageVersion', c_short),
        ('MajorSubsystemVersion', c_short),
        ('MinorSubsystemVersion', c_short),
        ('Win32VersionValue', c_uint),
        ('SizeOfImage', c_uint),
        ('SizeOfHeaders', c_uint),
        ('CheckSum', c_uint),
        ('Subsystem', c_short),
        ('DllCharacteristics', c_short),
        ('SizeOfStackReserve', c_uint),
        ('SizeOfStackCommit', c_uint),
        ('SizeOfHeapReserve', c_uint),
        ('SizeOfHeapCommit', c_uint),
        ('LoaderFlags', c_uint),
        ('NumberOfRvaAndSizes', c_uint)
        # omit the DataDirectory
    ]

class IMAGE_NT_HEADERS(Structure):
    _fields_ = [
        ('Signature', c_uint),
        ('FileHeader', IMAGE_FILE_HEADER),
        ('OptionalHeader', IMAGE_OPTIONAL_HEADER)
    ]

IMAGE_SIZEOF_SHORT_NAME = 8

class IMAGE_SECTION_HEADER_Misc(Union):
    _fields_ = [
        ('PhysicalAddress', c_uint),
        ('VirtualSize', c_uint)
    ]

class IMAGE_SECTION_HEADER(Structure):
    _fields_ = [
        ('Name', c_char * IMAGE_SIZEOF_SHORT_NAME),
        ('Misc', IMAGE_SECTION_HEADER_Misc),
        ('VirtualAddress', c_uint),
        ('SizeOfRawData', c_uint),
        ('PointerToRawData', c_uint),
        ('PointerToRelocations', c_uint),
        ('PointerToLinenumbers', c_uint),
        ('NumberOfRelocations', c_short),
        ('NumberOfLinenumbers', c_short),
        ('Characteristics', c_uint)
    ]

if __name__ == '__main__':
    if len(sys.argv) not in (2, 3):
        print 'Usage: %s <dump> [baseaddr]' % sys.argv[0]
        exit(0)

    # read the dump
    buf = file(sys.argv[1], 'rb').read()
    chunks = []
    while len(buf):
        base_addr, length = struct.unpack('2I', buf[:8])
        chunk, buf = buf[8:8+length], buf[8+length:]
        chunks.append((base_addr, length, chunk))

    # sort on base address
    chunks = sorted(chunks, key=lambda x: x[0])

    # print all the chunks
    print '\n'.join('0x%08x 0x%08x' % (x, y) for x, y, z in chunks)

    # determine base address
    base_address = sys.argv[2] if len(sys.argv) == 3 else 0x400000

    # TODO concat any sections that are split up, e.g. if there is a chunk at
    # address 0x401000 with length 1 and a chunk at 0x401001 with length 1,
    # then merge those chunks into one.
    # ...

    # dump all sections to file

    # find the section at the base address
    section = filter(lambda x: x[0] == base_address, chunks)
    assert len(section) == 1, 'No section found at the Base Address'

    # all the header data
    header_data = section[0][2]

    # read the image dos header
    image_dos_header = IMAGE_DOS_HEADER.from_buffer_copy(header_data)

    # read the image nt headers
    image_nt_headers = IMAGE_NT_HEADERS.from_buffer_copy(header_data,
        image_dos_header.e_lfanew)

    # output buffer
    buf = header_data

    # enumerate each section
    for x in xrange(image_nt_headers.FileHeader.NumberOfSections):

        # read the image section header
        image_section_header = IMAGE_SECTION_HEADER.from_buffer_copy(
            header_data, image_dos_header.e_lfanew + sizeof(c_uint) +
            sizeof(IMAGE_FILE_HEADER) + x * sizeof(IMAGE_SECTION_HEADER) +
            image_nt_headers.FileHeader.SizeOfOptionalHeader)

        # find the memory for this section
        data = filter(lambda x: x[0] == base_address +
            image_section_header.VirtualAddress, chunks)

        # prepend padding and append the data to the file
        buf += '\x00' * (image_section_header.PointerToRawData - len(buf))
        buf += data[0][2]

    file(sys.argv[1] + '.out', 'wb').write(buf)
