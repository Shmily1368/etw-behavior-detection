@ echo off
chcp 65001
set MyPython="C:\Program Files (x86)\Microsoft Visual Studio\Shared\Python39_64\python.exe"
set Index=%1%
del %Index%\gridResult.txt
echo %Index%\gridResult.txt
call grid1.bat %1 > "%Index%\gridResult.txt"
echo grid1end
echo %Index%\gridResult.txt
for /f "tokens=1,2,3 delims= " %%a in (%Index%\gridResult.txt) do (
  echo %Index% >> %Index%\Result.csv
  echo %%a >> %Index%\Result.csv
  echo %%b >> %Index%\Result.csv
  echo %%c >> %Index%\Result.csv
  echo libsvm-3.32\windows\svm-train -c %%a -g %%b %Index%\scale80.in %Index%\model.txt
  libsvm-3.32\windows\svm-train -c %%a -g %%b %Index%\scale80.in %Index%\model.txt
  libsvm-3.32\windows\svm-predict.exe %Index%\scale20.in %Index%\model.txt %Index%\tmpoutput20.txt >> %Index%\Result.csv
)