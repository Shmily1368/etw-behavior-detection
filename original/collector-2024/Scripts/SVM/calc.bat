@ echo off
chcp 65001
set MyPython="C:\Program Files (x86)\Microsoft Visual Studio\Shared\Python39_64\python.exe"
set /a count=12
for /l %%i in (1,1,%count%) do (
    echo This is loop %%i
	echo %%i\scale20.in
	echo %%i\tmpoutput20.txt
	%MyPython% calc.py --File1 %%i\scale20.in --File2 %%i\tmpoutput20.txt
)
pause