@ echo off
set MyPython="C:\Program Files (x86)\Microsoft Visual Studio\Shared\Python39_64\python.exe"
set PNG_PATH=%1%\scale80.png
set OUT_PATH=%1%\scale80.out
%MyPython% grid.py -svmtrain libsvm-3.32\windows\svm-train.exe -gnuplot null -out %OUT_PATH% -png %PNG_PATH% %1%\scale80.in