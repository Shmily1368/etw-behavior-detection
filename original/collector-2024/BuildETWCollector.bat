git submodule init
git submodule update

SET IN_VERSION=%~1%
SET PACK_PATH=%~2%
SET GIT_BRANCH_NAME=%~3%

set TEMP_DIR=%IN_VERSION%
echo %TEMP_DIR%
echo "%PACK_PATH%\pdb\%TEMP_DIR%"
md "%PACK_PATH%\pdb\%TEMP_DIR%"

echo "%PACK_PATH%\out\%TEMP_DIR%"
md "%PACK_PATH%\out\%TEMP_DIR%"

set BUILD_CONFIG=Release

set VCPROJ_FILE="%cd%\ETWDataCollectorRedesigned.sln"
echo 项目文件 : %VCPROJ_FILE%
echo 编译选项 : %BUILD_CONFIG%


"%MyMsBuild_2022%" %VCPROJ_FILE% /t:Build /p:Configuration=%BUILD_CONFIG% /p:WarningLevel=2 /p:Platform=x64 /flp:logfile=Log\PrintHelper.log;verbosity=normal
if ERRORLEVEL 1 goto ERROR_END
if not exist "%cd%\Release\x64\ETWDataCollectorRedesigned.exe" goto ERROR_END
echo %cd%\Release\x64\ETWDataCollectorRedesigned.pdb
echo "%PACK_PATH%\pdb\%TEMP_DIR%\x64\ETWDataCollectorRedesigned.pdb"
echo f | xcopy /S /I /Y %cd%\Release\x64\ETWDataCollectorRedesigned.pdb "%PACK_PATH%\pdb\%TEMP_DIR%\x64\ETWDataCollectorRedesigned.pdb"
if ERRORLEVEL 1 goto ERROR_END

echo "%cd%\Release\x64\ETWDataCollectorRedesigned.exe"
echo "%PACK_PATH%\out\%TEMP_DIR%\x64\ETWData.exe"
echo f | xcopy /S /I /Y "%cd%\Release\x64\ETWDataCollectorRedesigned.exe" "%PACK_PATH%\out\%TEMP_DIR%\x64\ETWData.exe"
if ERRORLEVEL 1 goto ERROR_END

echo ------SIGN_START------
:SIGN_RETRYA
"%MySignTool%" sign /r 123 /f "%PACK_PATH%\out\%TEMP_DIR%\x64\ETWData.exe"
if ERRORLEVEL 1 goto SIGN_RETRYA


"%MyMsBuild_2022%" %VCPROJ_FILE% /t:Build /p:Configuration=%BUILD_CONFIG% /p:WarningLevel=2 /p:Platform=Win32 /flp:logfile=Log\PrintHelper.log;verbosity=normal
if ERRORLEVEL 1 goto ERROR_END
if not exist "%cd%\Release\Win32\ETWDataCollectorRedesigned.exe" goto ERROR_END
echo %cd%\Release\Win32\ETWDataCollectorRedesigned.pdb
echo "%PACK_PATH%\pdb\%TEMP_DIR%\Win32\ETWDataCollectorRedesigned.pdb"
echo f | xcopy /S /I /Y %cd%\Release\Win32\ETWDataCollectorRedesigned.pdb "%PACK_PATH%\pdb\%TEMP_DIR%\Win32\ETWDataCollectorRedesigned.pdb"
if ERRORLEVEL 1 goto ERROR_END

echo "%cd%\Release\Win32\ETWDataCollectorRedesigned.exe"
echo "%PACK_PATH%\out\%TEMP_DIR%\Win32\ETWData.exe"
echo f | xcopy /S /I /Y "%cd%\Release\Win32\ETWDataCollectorRedesigned.exe" "%PACK_PATH%\out\%TEMP_DIR%\Win32\ETWData.exe"
if ERRORLEVEL 1 goto ERROR_END

echo ------SIGN_START------
:SIGN_RETRYB
"%MySignTool%" sign /r 123 /f "%PACK_PATH%\out\%TEMP_DIR%\Win32\ETWData.exe"
if ERRORLEVEL 1 goto SIGN_RETRYB


echo ------git checkout begin------
echo "%PACK_PATH%\ETWPackage\APTETWCollectorArchive"
echo %GIT_BRANCH_NAME%
git -C "%PACK_PATH%\ETWPackage\APTETWCollectorArchive" status
git -C "%PACK_PATH%\ETWPackage\APTETWCollectorArchive" fetch
git -C "%PACK_PATH%\ETWPackage\APTETWCollectorArchive" checkout %GIT_BRANCH_NAME%
echo ------git pull start------
git -C "%PACK_PATH%\ETWPackage\APTETWCollectorArchive" pull origin %GIT_BRANCH_NAME%
echo ------git pull end------
echo ------git checkout end------

echo "%PACK_PATH%\out\%TEMP_DIR%\x64\ETWData.exe"
echo "%PACK_PATH%\ETWPackage\APTETWCollectorArchive\64\Collector\ETWData.exe"
echo f | xcopy /S /I /Y "%PACK_PATH%\out\%TEMP_DIR%\x64\ETWData.exe" "%PACK_PATH%\ETWPackage\APTETWCollectorArchive\64\Collector\ETWData.exe"
if ERRORLEVEL 1 goto ERROR_END

echo "%PACK_PATH%\out\%TEMP_DIR%\Win32\ETWData.exe"
echo "%PACK_PATH%\ETWPackage\APTETWCollectorArchive\32\Collector\ETWData.exe"
echo f | xcopy /S /I /Y "%PACK_PATH%\out\%TEMP_DIR%\Win32\ETWData.exe" "%PACK_PATH%\ETWPackage\APTETWCollectorArchive\32\Collector\ETWData.exe"
if ERRORLEVEL 1 goto ERROR_END

echo ------git push begin------
git -C "%PACK_PATH%\ETWPackage\APTETWCollectorArchive" add .
git -C "%PACK_PATH%\ETWPackage\APTETWCollectorArchive" commit -m '%IN_VERSION%'
git -C "%PACK_PATH%\ETWPackage\APTETWCollectorArchive" push
echo ------git push end------

echo ------prepare package for sever begin------
%PACK_PATH%\bat\7z.exe a %PACK_PATH%\out\%TEMP_DIR%\Win32\%TEMP_DIR%.zip %PACK_PATH%\ETWPackage\APTETWCollectorArchive\32\Collector\*
%PACK_PATH%\bat\7z.exe a %PACK_PATH%\out\%TEMP_DIR%\x64\%TEMP_DIR%.zip %PACK_PATH%\ETWPackage\APTETWCollectorArchive\64\Collector\*

echo %date%
for /F "tokens=1-4 delims=/ " %%a in ('echo %date%') do (set week=%%a)
echo %week%
for /F "tokens=1-4 delims=/ " %%a in ('echo %date%') do (set year=%%b)
echo %year%
for /F "tokens=1-4 delims=/ " %%a in ('echo %date%') do (set month=%%c)
echo %month%
for /F "tokens=1-4 delims=/ " %%a in ('echo %date%') do (set day=%%d)
echo %day%
set TODAY=%year%%month%%day%
echo %TODAY%
echo ------prepare package for sever end------

net use x: \\127.0.0.1\Test\client_win "RDrd123$%%^" /user:"RD"
echo "%PACK_PATH%\pdb\%TEMP_DIR%\x64\ETWDataCollectorRedesigned.pdb"
echo "%PACK_PATH%\pdb\%TEMP_DIR%\Win32\ETWDataCollectorRedesigned.pdb"
echo "%PACK_PATH%\out\%TEMP_DIR%\x64\ETWData.exe"
echo "%PACK_PATH%\out\%TEMP_DIR%\Win32\ETWData.exe"

rem 组件
mkdir "x:\ETW-Windows\%TEMP_DIR%"
mkdir "x:\ETW-Windows\%TEMP_DIR%\x64"
mkdir "x:\ETW-Windows\%TEMP_DIR%\Win32"
echo f | xcopy /s /y "%PACK_PATH%\out\%TEMP_DIR%\x64\ETWData.exe" "x:\ETW-Windows\%TEMP_DIR%\x64\ETWData.exe"
echo f | xcopy /s /y "%PACK_PATH%\out\%TEMP_DIR%\Win32\ETWData.exe" "x:\ETW-Windows\%TEMP_DIR%\Win32\ETWData.exe"

rem pdb文件
mkdir "x:\pdb\ETW-Windows\%TEMP_DIR%"
mkdir "x:\pdb\ETW-Windows\%TEMP_DIR%\x64"
mkdir "x:\pdb\ETW-Windows\%TEMP_DIR%\Win32"
echo f | xcopy /s /y "%PACK_PATH%\pdb\%TEMP_DIR%\x64\ETWDataCollectorRedesigned.pdb" "x:\pdb\ETW-Windows\%TEMP_DIR%\x64\ETWDataCollectorRedesigned.pdb"
echo f | xcopy /s /y "%PACK_PATH%\pdb\%TEMP_DIR%\Win32\ETWDataCollectorRedesigned.pdb" "x:\pdb\ETW-Windows\%TEMP_DIR%\Win32\ETWDataCollectorRedesigned.pdb"

rem 服务器上传包
echo f | xcopy /s /y "%PACK_PATH%\out\%TEMP_DIR%\x64\%TEMP_DIR%.zip" "x:\ETW-Windows\%TEMP_DIR%\edr%TODAY%.zip"
echo f | xcopy /s /y "%PACK_PATH%\out\%TEMP_DIR%\x64\%TEMP_DIR%.zip" "x:\ETW-Windows\%TEMP_DIR%\edr%TODAY%_64.zip"
echo f | xcopy /s /y "%PACK_PATH%\out\%TEMP_DIR%\Win32\%TEMP_DIR%.zip" "x:\ETW-Windows\%TEMP_DIR%\edr%TODAY%_32.zip"

net use x: /delete

goto SUCCEED_END
:ERROR_END
echo ------FAILED------
@exit /b 1
:SUCCEED_END
echo ------SUCCEED------
@exit /b 0