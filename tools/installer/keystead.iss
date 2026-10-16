; Instalator KeyStead Manager (Inno Setup 6). Budowany przez tools/release_app.py:
;   ISCC /DAppVersion=1.0.0 /DSourceDir=<katalog z PyInstallera> /DOutputDir=<wyjście> keystead.iss
; Instalacja dla bieżącego użytkownika (bez uprawnień administratora) do %LOCALAPPDATA%\Programs.
; Dane użytkownika (~\.keystead, pliki sejfów) nie są usuwane przy odinstalowaniu.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{7C1E5B2A-4F3D-4E8B-9A61-2D5C8F0B3E47}
AppName=KeyStead Manager
AppVersion={#AppVersion}
AppVerName=KeyStead Manager {#AppVersion}
AppPublisher=KeyStead
AppPublisherURL=https://github.com/facior/KeyStead-Manager
DefaultDirName={autopf}\KeyStead Manager
DefaultGroupName=KeyStead Manager
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir={#OutputDir}
OutputBaseFilename=KeyStead-Manager-Setup-{#AppVersion}
SetupIconFile=..\..\ui\assets\keystead.ico
UninstallDisplayIcon={app}\KeyStead Manager.exe
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
VersionInfoVersion={#AppVersion}
VersionInfoProductName=KeyStead Manager

[Languages]
Name: "polish"; MessagesFile: "compiler:Languages\Polish.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[InstallDelete]
; Pliki poprzedniej wersji (biblioteki mogą się różnić między wydaniami)
Type: filesandordirs; Name: "{app}\_internal"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\KeyStead Manager"; Filename: "{app}\KeyStead Manager.exe"
Name: "{autodesktop}\KeyStead Manager"; Filename: "{app}\KeyStead Manager.exe"; Tasks: desktopicon

[Run]
; Instalacja ręczna: pole „Uruchom” na końcu kreatora
Filename: "{app}\KeyStead Manager.exe"; Description: "{cm:LaunchProgram,KeyStead Manager}"; Flags: nowait postinstall skipifsilent
; Aktualizacja z aplikacji (tryb cichy): uruchom ponownie po instalacji
Filename: "{app}\KeyStead Manager.exe"; Flags: nowait; Check: WizardSilent
