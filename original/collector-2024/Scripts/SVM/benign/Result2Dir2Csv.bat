@ echo off
chcp 65001
set MyPython="C:\Program Files (x86)\Microsoft Visual Studio\Shared\Python39_64\python.exe"
set /a count=12

set DstDir=allfeature_M1
for /l %%i in (1,1,%count%) do (
    echo This is loop %%i
	echo %%i_af
	echo %MyPython% Result2Dir2Result2.py --Dir "%DstDir%\%%i_af" --DstPath "%DstDir%\%%i_af.out" 
	echo %MyPython% out2csv.py --Path "%DstDir%\%%i_af.out" --DstPath "%DstDir%\%%i_af.csv"
	%MyPython% Result2Dir2Result2.py --Dir "%DstDir%\%%i_af" --DstPath "%DstDir%\%%i_af.out" 
	%MyPython% out2csv.py --Path "%DstDir%\%%i_af.out" --DstPath "%DstDir%\%%i_af.csv"
)

set DstDir=allfeature_M1_1
for /l %%i in (1,1,%count%) do (
    echo This is loop %%i
	echo %%i_af
	echo %MyPython% Result2Dir2Result2.py --Dir "%DstDir%\%%i_af" --DstPath "%DstDir%\%%i_af.out" 
	echo %MyPython% out2csv.py --Path "%DstDir%\%%i_af.out" --DstPath "%DstDir%\%%i_af.csv"
	%MyPython% Result2Dir2Result2.py --Dir "%DstDir%\%%i_af" --DstPath "%DstDir%\%%i_af.out" 
	%MyPython% out2csv.py --Path "%DstDir%\%%i_af.out" --DstPath "%DstDir%\%%i_af.csv"
)

set DstDir=allfeature_M2
for /l %%i in (1,1,%count%) do (
    echo This is loop %%i
	echo %%i_af
	echo %MyPython% Result2Dir2Result2.py --Dir "%DstDir%\%%i_af" --DstPath "%DstDir%\%%i_af.out" 
	echo %MyPython% out2csv.py --Path "%DstDir%\%%i_af.out" --DstPath "%DstDir%\%%i_af.csv"
	%MyPython% Result2Dir2Result2.py --Dir "%DstDir%\%%i_af" --DstPath "%DstDir%\%%i_af.out" 
	%MyPython% out2csv.py --Path "%DstDir%\%%i_af.out" --DstPath "%DstDir%\%%i_af.csv"
)

set DstDir=allfeature_setup
for /l %%i in (1,1,%count%) do (
    echo This is loop %%i
	echo %%i_af
	echo %MyPython% Result2Dir2Result2.py --Dir "%DstDir%\%%i_af" --DstPath "%DstDir%\%%i_af.out" 
	echo %MyPython% out2csv.py --Path "%DstDir%\%%i_af.out" --DstPath "%DstDir%\%%i_af.csv"
	%MyPython% Result2Dir2Result2.py --Dir "%DstDir%\%%i_af" --DstPath "%DstDir%\%%i_af.out" 
	%MyPython% out2csv.py --Path "%DstDir%\%%i_af.out" --DstPath "%DstDir%\%%i_af.csv"
)

pause