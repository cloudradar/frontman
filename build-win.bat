CD /D "%~dp0"
FOR /F "tokens=* USEBACKQ" %%F IN (`git describe --always --tag`) DO (
SET frontman_version=%%F
)
COPY example.config.toml frontman.conf
COPY dist\windows_386\frontman.exe frontman.exe
go-msi.exe make --src pkg-scripts\msi-templates --msi dist/frontman_%frontman_version%_Windows_i386.msi --version %frontman_version% --arch 386
DEL frontman.exe
COPY dist\windows_amd64\frontman.exe frontman.exe
go-msi.exe make --src pkg-scripts\msi-templates --msi dist/frontman_%frontman_version%_Windows_x86_64.msi --version %frontman_version% --arch amd64
DEL frontman.exe
DEL frontman.conf