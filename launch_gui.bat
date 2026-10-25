@echo off
rem ==============================================================================
rem ARECON GUI Launcher (Windows Batch) — By Rakshit Walia
rem Copyright (c) 2026 Rakshit Walia. All rights reserved.
rem License: MIT License
rem Theme: Clean White Background, Red Buttons, Black Text
rem ==============================================================================

set SCRIPT_DIR=%~dp0

echo ==============================================================
echo  ARECON 2.0 -- Web Application Reconnaissance GUI
echo  Author: RAKSHIT WALIA
echo  Theme:  White Background ^| Red Buttons ^| Black Text
echo ==============================================================

if "%1"=="--web" goto run_web
if "%1"=="-w" goto run_web

:run_desktop
echo [*] Launching ARECON Native Desktop Window...
python "%SCRIPT_DIR%arecon_gui.py"
goto end

:run_web
echo [*] Launching ARECON Web Dashboard in your browser...
python "%SCRIPT_DIR%arecon_web.py"
goto end

:end
