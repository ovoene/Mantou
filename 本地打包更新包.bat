@echo off
setlocal
REM ===========================================================================
REM  Local packaging - builds the Linux self-update packages on this machine.
REM
REM  Output: mantou-Ver_x.y.z-linux-<arch>.tar.gz in the project root (binary +
REM  Ed25519 signature), ready for the panel's "upload update package".
REM  It never commits, tags or pushes anything - publishing is the job of the
REM  other script (the release .bat -> release.sh).
REM
REM  Usage:  <this file>                 asks for the version number
REM          <this file> 1.2.0           version given, no question asked
REM          <this file> 1.2.0 arm64     version given, arm64 only
REM
REM  All logic and every Chinese message live in package.sh. This file only finds
REM  Git Bash and runs it - the same approach as the release .bat (its Git Bash
REM  search is copied verbatim below). It stays plain ASCII on purpose: cmd
REM  mis-reads batch files that contain UTF-8 Chinese text (lines get split in the
REM  wrong places and fragments of comments run as commands, differently under
REM  code page 936 and 65001), while bash reads UTF-8 scripts correctly.
REM ===========================================================================

REM ---- double-click detection: pause at the end so the window does not vanish ----
REM Explorer starts a .bat as  cmd.exe /c ""X:\...\name.bat" "  (note the trailing " ");
REM PowerShell uses  cmd.exe /c ""X:\...\name.bat""  and a cmd prompt does not contain
REM the script name at all. Quotes are swapped for # first: a quote left inside the
REM variable would break the if syntax.
set "MT_PAUSE="
setlocal EnableDelayedExpansion
set "MT_CCL=!CMDCMDLINE!"
set "MT_CCL=!MT_CCL:"=#!"
if /i not "!MT_CCL:%~nx0# #=!"=="!MT_CCL!" set "MT_PAUSE=1"
endlocal & set "MT_PAUSE=%MT_PAUSE%"

REM package.sh lives next to this file; work from there even when double-clicked.
cd /d "%~dp0"

REM ---- locate Git Bash's bash.exe ----
set "BASH_EXE="
if exist "%ProgramFiles%\Git\bin\bash.exe" set "BASH_EXE=%ProgramFiles%\Git\bin\bash.exe"
if not defined BASH_EXE if exist "%ProgramFiles(x86)%\Git\bin\bash.exe" set "BASH_EXE=%ProgramFiles(x86)%\Git\bin\bash.exe"
if not defined BASH_EXE if exist "%LocalAppData%\Programs\Git\bin\bash.exe" set "BASH_EXE=%LocalAppData%\Programs\Git\bin\bash.exe"

if not defined BASH_EXE (
  echo [ERROR] Git Bash not found.
  echo         Install Git for Windows first: https://git-scm.com/download/win
  set "MT_RC=1"
  goto :finish
)

REM ---- run package.sh (forward all arguments) ----
"%BASH_EXE%" package.sh %*
set "MT_RC=%errorlevel%"

:finish
if defined MT_PAUSE (
  echo.
  pause
)
exit /b %MT_RC%
