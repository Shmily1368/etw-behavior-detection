@ echo off
chcp 65001

set MyPython="C:\Program Files (x86)\Microsoft Visual Studio\Shared\Python39_64\python.exe"
set TempDir=allfeature_M1
%MyPython% benign.py --InputFile "%TempDir%.out" --DstDir "%TempDir%"
set TempDir=allfeature_M1_1
%MyPython% benign.py --InputFile "%TempDir%.out" --DstDir "%TempDir%"
set TempDir=allfeature_M2
%MyPython% benign.py --InputFile "%TempDir%.out" --DstDir "%TempDir%"
set TempDir=allfeature_setup
%MyPython% benign.py --InputFile "%TempDir%.out" --DstDir "%TempDir%"

pause