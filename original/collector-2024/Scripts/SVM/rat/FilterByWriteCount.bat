@ echo off
chcp 65001

set MyPython="C:\Users\mayn\AppData\Local\Programs\Python\Python39\python.exe"
set TempDir=Data_sample_Out
set TempDir1=Data_total_Out
set Index=1
%MyPython% FilterByWriteCount.py --InputFile %TempDir%\%Index%_af.out --DstFile %TempDir%\%Index%_aff.out --Filter 16
%MyPython% FilterByWriteCount.py --InputFile %TempDir1%\%Index%_af.out --DstFile %TempDir1%\%Index%_aff.out --Filter 16
set Index=2
%MyPython% FilterByWriteCount.py --InputFile %TempDir%\%Index%_af.out --DstFile %TempDir%\%Index%_aff.out --Filter 24
%MyPython% FilterByWriteCount.py --InputFile %TempDir1%\%Index%_af.out --DstFile %TempDir1%\%Index%_aff.out --Filter 24
set Index=3
%MyPython% FilterByWriteCount.py --InputFile %TempDir%\%Index%_af.out --DstFile %TempDir%\%Index%_aff.out --Filter 27
%MyPython% FilterByWriteCount.py --InputFile %TempDir1%\%Index%_af.out --DstFile %TempDir1%\%Index%_aff.out --Filter 27
set Index=4
%MyPython% FilterByWriteCount.py --InputFile %TempDir%\%Index%_af.out --DstFile %TempDir%\%Index%_aff.out --Filter 35
%MyPython% FilterByWriteCount.py --InputFile %TempDir1%\%Index%_af.out --DstFile %TempDir1%\%Index%_aff.out --Filter 35
set Index=5
%MyPython% FilterByWriteCount.py --InputFile %TempDir%\%Index%_af.out --DstFile %TempDir%\%Index%_aff.out --Filter 34
%MyPython% FilterByWriteCount.py --InputFile %TempDir1%\%Index%_af.out --DstFile %TempDir1%\%Index%_aff.out --Filter 34
set Index=6
%MyPython% FilterByWriteCount.py --InputFile %TempDir%\%Index%_af.out --DstFile %TempDir%\%Index%_aff.out --Filter 49
%MyPython% FilterByWriteCount.py --InputFile %TempDir1%\%Index%_af.out --DstFile %TempDir1%\%Index%_aff.out --Filter 49
set Index=7
%MyPython% FilterByWriteCount.py --InputFile %TempDir%\%Index%_af.out --DstFile %TempDir%\%Index%_aff.out --Filter 41
%MyPython% FilterByWriteCount.py --InputFile %TempDir1%\%Index%_af.out --DstFile %TempDir1%\%Index%_aff.out --Filter 41
set Index=8
%MyPython% FilterByWriteCount.py --InputFile %TempDir%\%Index%_af.out --DstFile %TempDir%\%Index%_aff.out --Filter 47
%MyPython% FilterByWriteCount.py --InputFile %TempDir1%\%Index%_af.out --DstFile %TempDir1%\%Index%_aff.out --Filter 47
set Index=9
%MyPython% FilterByWriteCount.py --InputFile %TempDir%\%Index%_af.out --DstFile %TempDir%\%Index%_aff.out --Filter 61
%MyPython% FilterByWriteCount.py --InputFile %TempDir1%\%Index%_af.out --DstFile %TempDir1%\%Index%_aff.out --Filter 61
set Index=10
%MyPython% FilterByWriteCount.py --InputFile %TempDir%\%Index%_af.out --DstFile %TempDir%\%Index%_aff.out --Filter 59
%MyPython% FilterByWriteCount.py --InputFile %TempDir1%\%Index%_af.out --DstFile %TempDir1%\%Index%_aff.out --Filter 59
set Index=11
%MyPython% FilterByWriteCount.py --InputFile %TempDir%\%Index%_af.out --DstFile %TempDir%\%Index%_aff.out --Filter 54
%MyPython% FilterByWriteCount.py --InputFile %TempDir1%\%Index%_af.out --DstFile %TempDir1%\%Index%_aff.out --Filter 54
set Index=12
%MyPython% FilterByWriteCount.py --InputFile %TempDir%\%Index%_af.out --DstFile %TempDir%\%Index%_aff.out --Filter 54
%MyPython% FilterByWriteCount.py --InputFile %TempDir1%\%Index%_af.out --DstFile %TempDir1%\%Index%_aff.out --Filter 54


pause