#ifndef AppVersion
  #error AppVersion must be provided by the build
#endif

[Setup]
AppId={{C866973C-2927-48E1-98F8-A99560E5341E}
AppName=PortSpecter
AppVersion={#AppVersion}
AppPublisher=PortSpecter
AppPublisherURL=https://github.com/Gorke07/PortSpecter
DefaultDirName={localappdata}\Programs\PortSpecter
DefaultGroupName=PortSpecter
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
LicenseFile=..\..\LICENSE
SetupIconFile=..\..\assets\icons\portspecter.ico
UninstallDisplayIcon={app}\portspecter.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Tasks]
Name: desktopicon; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "..\..\target\release\portspecter.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\NOTICE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\README.tr.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\PortSpecter"; Filename: "{app}\portspecter.exe"
Name: "{autodesktop}\PortSpecter"; Filename: "{app}\portspecter.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\portspecter.exe"; Description: "Launch PortSpecter"; Flags: nowait postinstall skipifsilent
