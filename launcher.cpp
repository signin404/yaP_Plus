[Settings]
; --- User Variables ---
uservar = GameName :: MyAwesomeGame
uservar = SaveBackupDir :: D:\Game_Backups\{GameName}

; --- Main Application ---
application = {Local}\{GameName}\bin\game.exe
workdir = {EXEPATH}
commandline = -nolog -user %USERNAME%
multiple = 1

; --- Link Settings ---
hardlink = {EXEPATH}\config.ini :: {Roaming}\{GameName}\config.ini
symlink = {EXEPATH}\Saves\ :: {Roaming}\{GameName}\Saves\

; --- Wait Process Settings ---
waitcheck = 10
waitprocess = data_processor.exe

; --- Foreground Monitoring Settings ---
foregroundcheck = 1
foreground = game.exe
suspend = chrome.exe

; --- Automatic Backup Settings ---
autosavetime = 10
autosavedir = {Roaming}\{GameName}\Saves :: {SaveBackupDir}\Saves
autosavefile = {Roaming}\{GameName}\config.ini :: {SaveBackupDir}\config.ini