@echo off
REM NetScope launcher: builds on first run, then starts the app with your arguments.
setlocal
chcp 65001 >nul
set DIR=%~dp0
cd /d "%DIR%"

if not exist "build\install\netscope\bin\netscope.bat" (
    echo [netscope] first build, may take a minute...
    call gradlew.bat installDist --console=plain -q
    if errorlevel 1 exit /b %ERRORLEVEL%
)

call "build\install\netscope\bin\netscope.bat" %*
exit /b %ERRORLEVEL%
