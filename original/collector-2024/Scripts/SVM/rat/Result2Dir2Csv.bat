@ echo off
chcp 65001
set MyPython="C:\Program Files (x86)\Microsoft Visual Studio\Shared\Python39_64\python.exe"
set /a count=12

set DstDir=Data_sample_Out
for /l %%i in (1,1,%count%) do (
    echo This is loop %%i
	echo %%i_af
	echo %MyPython% Result2Dir2Result2.py --Dir "%DstDir%\%%i_af" --DstPath "%DstDir%\%%i_af.out" 
	echo %MyPython% out2csv.py --Path "%DstDir%\%%i_af.out" --DstPath "%DstDir%\%%i_af.csv"
	%MyPython% Result2Dir2Result2.py --Dir "%DstDir%\%%i_af" --DstPath "%DstDir%\%%i_af.out" 
	%MyPython% out2csv.py --Path "%DstDir%\%%i_af.out" --DstPath "%DstDir%\%%i_af.csv"
	
	echo %%i_10af
	%MyPython% Result2Dir2Result2.py --Dir "%DstDir%\%%i_10af" --DstPath "%DstDir%\%%i_10af.out" --LineStart "0" 
	%MyPython% out2csv.py --Path "%DstDir%\%%i_10af.out" --DstPath "%DstDir%\%%i_10af.csv"
)

set DstDir=Data_total_Out
for /l %%i in (1,1,%count%) do (
    echo This is loop %%i
	echo %%i_af
	echo %MyPython% Result2Dir2Result2.py --Dir "%DstDir%\%%i_af" --DstPath "%DstDir%\%%i_af.out" 
	echo %MyPython% out2csv.py --Path "%DstDir%\%%i_af.out" --DstPath "%DstDir%\%%i_af.csv"
	%MyPython% Result2Dir2Result2.py --Dir "%DstDir%\%%i_af" --DstPath "%DstDir%\%%i_af.out" 
	%MyPython% out2csv.py --Path "%DstDir%\%%i_af.out" --DstPath "%DstDir%\%%i_af.csv"
	
	echo %%i_10af
	%MyPython% Result2Dir2Result2.py --Dir "%DstDir%\%%i_10af" --DstPath "%DstDir%\%%i_10af.out" --LineStart "0" 
	%MyPython% out2csv.py --Path "%DstDir%\%%i_10af.out" --DstPath "%DstDir%\%%i_10af.csv"
)

pause