@echo off
setlocal
set "GHIDRA_MCP_ALLOW_SCRIPTS=1"
cd /d "C:\bin\ghidra_12.1.2_PUBLIC"
if errorlevel 1 exit /b 1
call "C:\bin\ghidra_12.1.2_PUBLIC\ghidraRun.bat"
exit /b %errorlevel%
