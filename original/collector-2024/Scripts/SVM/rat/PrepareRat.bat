@ echo off
chcp 65001

set MyPython="C:\Program Files (x86)\Microsoft Visual Studio\Shared\Python39_64\python.exe"
set TempDir=Data_sample
%MyPython% Rat.py --InputDir "%TempDir%" --DstDir "%TempDir%_Out"
set TempDir=Data_total
%MyPython% Rat.py --InputDir "%TempDir%" --DstDir "%TempDir%_Out"
pause