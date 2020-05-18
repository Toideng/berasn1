call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" x64
rem cl -DTARGET_WIN32 berasn1_win.cpp server_win.cpp -Fe"server.exe"
cl -DTARGET_WIN32 berasn1_win.cpp client_win.cpp -Fe"client.exe"
pause
