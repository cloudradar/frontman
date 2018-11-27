SET build_dir=C:\Users\hero\frontman_ci\build_msi\%1
SET frontman_version=%2
SET cert_pass=%3

SET PATH=%PATH%;C:\Program Files (x86)\WiX Toolset v3.11\bin;c:\Program Files (x86)\Windows Kits\10\bin\10.0.17134.0\x86;C:\Program Files\go-msi
CD %build_dir%


COPY dist\frontman_386.exe frontman.exe
go-msi make --src pkg-scripts\msi-templates --msi dist/frontman_32.msi --version %frontman_version% --arch 386
DEL frontman.exe

COPY dist\frontman_64.exe frontman.exe
go-msi make --src pkg-scripts\msi-templates --msi dist/frontman_64.msi --version %frontman_version% --arch amd64
DEL frontman.exe

signtool sign /t http://timestamp.comodoca.com /f "C:\Users\hero\frontman_ci\build_msi\cloudradar.io.p12" /p %cert_pass% dist/frontman_32.msi
signtool sign /t http://timestamp.comodoca.com /f "C:\Users\hero\frontman_ci\build_msi\cloudradar.io.p12" /p %cert_pass% dist/frontman_64.msi
