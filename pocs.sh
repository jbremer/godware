cd pocs
make

if [ $# -ne 1 ]
then
    ../../../../ia32/bin/pin -t ../obj-ia32/godware.dll -- *.exe
else
    ../../../../ia32/bin/pin -t ../obj-ia32/godware.dll -- $1.exe
fi
