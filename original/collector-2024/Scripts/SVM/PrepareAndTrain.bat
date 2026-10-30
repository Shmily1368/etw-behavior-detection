@echo off
setlocal enabledelayedexpansion
set MyPython="C:\Program Files (x86)\Microsoft Visual Studio\Shared\Python39_64\python.exe"
set /a count=12

set DstDir=allfeature_M1
for /l %%i in (1,1,%count%) do (
    echo This is loop %%i
	echo benign\%DstDir%\%%i_af.out
	echo benign\%DstDir%\%%i_af_marked.out
	(for /f "tokens=*" %%a in (benign\%DstDir%\%%i_af.out) do (
		set "line=%%a"
		echo 0 !line!
	)) > benign\%DstDir%\%%i_af_marked.out
)

set DstDir=allfeature_M1_1
for /l %%i in (1,1,%count%) do (
    echo This is loop %%i
	echo benign\%DstDir%\%%i_af.out
	echo benign\%DstDir%\%%i_af_marked.out
	(for /f "tokens=*" %%a in (benign\%DstDir%\%%i_af.out) do (
		set "line=%%a"
		echo 0 !line!
	)) > benign\%DstDir%\%%i_af_marked.out
)

set DstDir=allfeature_M2
for /l %%i in (1,1,%count%) do (
    echo This is loop %%i
	echo benign\%DstDir%\%%i_af.out
	echo benign\%DstDir%\%%i_af_marked.out
	(for /f "tokens=*" %%a in (benign\%DstDir%\%%i_af.out) do (
		set "line=%%a"
		echo 0 !line!
	)) > benign\%DstDir%\%%i_af_marked.out
)

set DstDir=allfeature_setup
for /l %%i in (1,1,%count%) do (
    echo This is loop %%i
	echo benign\%DstDir%\%%i_af.out
	echo benign\%DstDir%\%%i_af_marked.out
	(for /f "tokens=*" %%a in (benign\%DstDir%\%%i_af.out) do (
		set "line=%%a"
		echo 0 !line!
	)) > benign\%DstDir%\%%i_af_marked.out
)

set DstDir=Data_sample_Out
for /l %%i in (1,1,%count%) do (
    echo This is loop %%i
	echo rat\%DstDir%\%%i_af.out
	echo rat\%DstDir%\%%i_af_marked.out
	(for /f "tokens=*" %%a in (rat\%DstDir%\%%i_af.out) do (
		set "line=%%a"
		echo 1 !line!
	)) > rat\%DstDir%\%%i_af_marked.out
)

set DstDir=Data_total_Out
for /l %%i in (1,1,%count%) do (
    echo This is loop %%i
	echo rat\%DstDir%\%%i_af.out
	echo rat\%DstDir%\%%i_af_marked.out
	(for /f "tokens=*" %%a in (rat\%DstDir%\%%i_af.out) do (
		set "line=%%a"
		echo 1 !line!
	)) > rat\%DstDir%\%%i_af_marked.out
)

for /l %%i in (1,1,%count%) do (
    echo This is loop %%i
	mkdir %%i
	echo benign\allfeature_M1\%%i_af_marked.out
	echo benign\allfeature_M1_1\%%i_af_marked.out
	echo benign\allfeature_M2\%%i_af_marked.out
	echo benign\allfeature_setup\%%i_af_marked.out
	echo rat\Data_sample_Out\%%i_af_marked.out
	echo rat\Data_total_Out\%%i_af_marked.out
	(type benign\allfeature_M1\%%i_af_marked.out ^& type benign\allfeature_M1_1\%%i_af_marked.out ^& type benign\allfeature_M2\%%i_af_marked.out ^& type benign\allfeature_setup\%%i_af_marked.out ^& type rat\Data_sample_Out\%%i_af_marked.out ^& type rat\Data_total_Out\%%i_af_marked.out) > %%i\Feature_All.out
	(type benign\allfeature_M1\%%i_af_marked.out ^& type benign\allfeature_M1_1\%%i_af_marked.out ^& type benign\allfeature_M2\%%i_af_marked.out ^& type benign\allfeature_setup\%%i_af_marked.out ) > %%i\Feature_benign.out
	(type rat\Data_sample_Out\%%i_af_marked.out ^& type rat\Data_total_Out\%%i_af_marked.out) > %%i\Feature_rat.out
	%MyPython% Remove0Column.py --InputFile "%%i\Feature_All.out" --InputFile1 "%%i\Feature_benign.out" --InputFile2 "%%i\Feature_rat.out" --DstFile1 "%%i\Feature_benign_af.out" --DstFile2 "%%i\Feature_rat_af.out"
	%MyPython% shuffle.py --InputFile "%%i\Feature_benign_af.out" --ShuffleTempFile "%%i\shuffle_benign.in" --DstFile1 "%%i\shuffle80_benign.in" --DstFile2 "%%i\shuffle20_benign.in" --Proportion 0.8
	%MyPython% shuffle.py --InputFile "%%i\Feature_rat_af.out" --ShuffleTempFile "%%i\shuffle_rat.in" --DstFile1 "%%i\shuffle80_rat.in" --DstFile2 "%%i\shuffle20_rat.in" --Proportion 0.8
	(type %%i\shuffle80_rat.in ^& type %%i\shuffle80_benign.in) > %%i\shuffle80.in
	(type %%i\shuffle20_rat.in ^& type %%i\shuffle20_benign.in) > %%i\shuffle20.in
	libsvm-3.32\windows\svm-scale.exe -l 0 -u 1 -s %%i\range_1.txt %%i\shuffle80.in > %%i\scale80.in 
	libsvm-3.32\windows\svm-scale.exe -s %%i\range.txt %%i\shuffle80.in > %%i\scale80.in 
	libsvm-3.32\windows\svm-scale.exe -r %%i\range.txt %%i\shuffle20.in > %%i\scale20.in 
	start grid.bat %%i
)