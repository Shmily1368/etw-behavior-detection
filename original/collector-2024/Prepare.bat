
::@echo off

echo f | xcopy /Y "format_Win7_filter_onlydetect_hardcode_encrypt.txt" "Debug\x64\format_Win7_filter_onlydetect_hardcode.txt"
echo f | xcopy /Y "format_Win10_filter_onlydetect_hardcode_encrypt.txt" "Debug\x64\format_Win10_filter_onlydetect_hardcode.txt"

echo f | xcopy /Y "format_Win7_filter_onlydetect_hardcode_encrypt.txt" "Release\x64\format_Win7_filter_onlydetect_hardcode.txt"
echo f | xcopy /Y "format_Win10_filter_onlydetect_hardcode_encrypt.txt" "Release\x64\format_Win10_filter_onlydetect_hardcode.txt"

echo f | xcopy /Y "format_Win7_filter_onlydetect_hardcode_86_encrypt.txt" "Debug\win32\format_Win7_filter_onlydetect_hardcode.txt"
echo f | xcopy /Y "format_Win10_filter_onlydetect_hardcode_86_encrypt.txt" "Debug\win32\format_Win10_filter_onlydetect_hardcode.txt"

echo f | xcopy /Y "format_Win7_filter_onlydetect_hardcode_86_encrypt.txt" "Release\win32\format_Win7_filter_onlydetect_hardcode.txt"
echo f | xcopy /Y "format_Win10_filter_onlydetect_hardcode_86_encrypt.txt" "Release\win32\format_Win10_filter_onlydetect_hardcode.txt"

for %%a in (Debug Release) do (
    for %%b in (win32 x64) do (
		
		echo f | xcopy /Y "LogConfig.properites" "%%a\%%b\"
		echo f | xcopy /Y "rule.lst" "%%a\%%b\"
        xcopy /S /I /Y "ThirdPart\file\%%b\" "%%a\%%b\tool\file\"
        xcopy /S /I /Y "ThirdPart\sdhash\%%b\sdhash-gpu-beta\" "%%a\%%b\tool\sdhash\sdhash-gpu-beta\"
        xcopy /I /Y "ThirdPart\sdhash\%%b\*.txt" "%%a\%%b\tool\sdhash\"
        xcopy /I /Y "ThirdPart\sdhash\%%b\*.exe" "%%a\%%b\tool\sdhash\"
        xcopy /I /Y "ThirdPart\sdhash\%%b\*.dll" "%%a\%%b\tool\sdhash\"
		
        xcopy /S /I /Y "API.csv" "%%a\%%b\"
        xcopy /S /I /Y "useless_cs.csv" "%%a\%%b\"
		
        xcopy /S /I /Y "ThirdPart\zlib\bin\%%a\%%b\*.dll" "%%a\%%b\"
        xcopy /S /I /Y "ThirdPart\lz4\bin\%%a\%%b\*.dll" "%%a\%%b\"
        xcopy /S /I /Y "ThirdPart\librdkafka\bin\%%a\%%b\rdkafka.dll" "%%a\%%b\"
        xcopy /S /I /Y "ThirdPart\protobuf\bin\%%a\%%b\*.dll" "%%a\%%b\"
        xcopy /S /I /Y "ThirdPart\log4cplus\bin\%%a\%%b\*.dll" "%%a\%%b\"
        xcopy /S /I /Y "ThirdPart\snappy\bin\%%a\%%b\*.dll" "%%a\%%b\"
        xcopy /S /I /Y "ThirdPart\clamav\%%b\libclamav.dll" "%%a\%%b\"
        xcopy /S /I /Y "ThirdPart\boost\bin\%%a\%%b\*boost_program_options*.dll" "%%a\%%b\"
        xcopy /S /I /Y "gen\%%b\%%a\" "%%a\%%b\"
    )
)


