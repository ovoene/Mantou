@echo off
setlocal
REM release.bat - one-click release entry for Windows
REM Usage: release.bat 1.2.0   or   release.bat (interactive version input)
REM This wrapper locates Git Bash and runs release.sh, so you can run it
REM from cmd/PowerShell without the WSL bash hijack issue.

REM ---- locate Git Bash's bash.exe ----
set "BASH_EXE="
if exist "%ProgramFiles%\Git\bin\bash.exe" set "BASH_EXE=%ProgramFiles%\Git\bin\bash.exe"
if not defined BASH_EXE if exist "%ProgramFiles(x86)%\Git\bin\bash.exe" set "BASH_EXE=%ProgramFiles(x86)%\Git\bin\bash.exe"
if not defined BASH_EXE if exist "%LocalAppData%\Programs\Git\bin\bash.exe" set "BASH_EXE=%LocalAppData%\Programs\Git\bin\bash.exe"

if not defined BASH_EXE (
  echo [ERROR] Git Bash not found.
  echo         Install Git for Windows first: https://git-scm.com/download/win
  exit /b 1
)

REM ---- run release.sh (forward all arguments) ----
"%BASH_EXE%" release.sh %*
exit /b %errorlevel%
