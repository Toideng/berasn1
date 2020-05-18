echo "updated"
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" x64
cl -FC -Fo -Zi -DTARGET_WIN32 berasn1_win.cpp
pause
