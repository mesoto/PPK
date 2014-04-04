# _______________________________________________________________________________
#
#
# _______________________________________________________________________________

VCB = "C:\Program Files\Microsoft Visual Studio 8\VC\vcpackages\vcbuild.exe"
ISC = "C:\Program Files\Inno Setup 5\ISCC.exe"
RAR = "C:\Tools\rar.exe"
MD5 = "C:\Tools\MD5.exe"

all:
    $(VCB) PPK.sln "Release|Win32"
    $(ISC) "Media\PPK.iss"
    $(RAR) f -r PPK.rar
    copy /b Media\Build\PPKWin32Install.exe Media\Build\PPKWin32Install_exe
    $(MD5) Media\Build\PPKWin32Install.exe
    $(MD5) Media\*.*

clean:
    $(VCB) /c PPK.sln "Release|Win32"
    del Media\Build\PPKWin32Install.exe >nul
    del Media\Build\PPKWin32Install_exe >nul
