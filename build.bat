call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" x64
cl -DTARGET_WIN32 -EHsc berasn1_win.cpp server_win.cpp -Fe"server.exe"
cl -DTARGET_WIN32 -EHsc berasn1_win.cpp client_win.cpp -Fe"client.exe"
rem cl -DTARGET_WIN32 -c client_win.cpp -Fe"client.obj"
rem cl -DTARGET_WIN32 -c berasn1_win.cpp -Fe"berasn1.obj"
pause
