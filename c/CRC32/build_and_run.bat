@echo off
call "D:\Utils\VisualStudio\Community\VC\Auxiliary\Build\vcvars64.bat"
cl /utf-8 /Fe:main.exe main.c crc32.c
if %errorlevel% neq 0 exit /b %errorlevel%
main.exe
