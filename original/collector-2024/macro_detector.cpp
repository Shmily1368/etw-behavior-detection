/*********************************************************************************
*
* Written by : Chunlin
* Create Time : 2018-09-11
* Last Upate : 2018-09-12
*
*********************************************************************************/


/*********************************************************************************
*
*HISTORY:
*I've tried to use Pythonxx.lib(Official) to call Python modules with arguments,
*but there are two problems:
*1: Cannot load the module successfully by using PyImport_ImportModule, the return
* value is always null;
*2: The main function in this module doesn't have parameters, I don't know how to
* pass parameters.
*
*So I try to call the Python script by cmd, get and analyze the output
*
*TODO:
*
*
*3. determine which file is to be scanned (whether a macro document could be run
* by commanline with a wrong file extension) 
*4. removing duplicated 
*
*Finished:
*1. find the installation path of oletools
*2. find the version of Python(2.x and 3.x use different scripts)
*********************************************************************************/

#include "stdafx.h"
#include "macro_detector.h"
#include "macro_detector/vbaParser.h"
#include "macro_detector/tool_functions_macro.h"
#include "tool_functions.h"

#include <windows.h>



/*
DESCRIPTION:
whether a file is Microsoft Office docucment
whether the document contains macro
whether the macro is malicious

INPUT
file_path : the path to the target file which is going to be checked

RETURN
- 8: No Macro (As EVENT_RECORD_DEFAULT_DATA_PARAMETER_VALUE == 0, so 0 could not be assigned to it. Using 8 instead.)
- 1: Not MS Office
- 2: Macro OK
- 10: ERROR
- 20: SUSPICIOUS
- 4: Wrong Path(May be a directory)
*/


void MacroDetector::Init()
{
	std::ifstream fp("macro_enable_app.ini", ios::in);
	String read_buf;
	while (getline(fp, read_buf))
	{
		m_usetMacroEnableApps.insert(StringUtil::ToLowerCase(read_buf));
	}
}

bool MacroDetector::IsMacroEnableApp(const String& app_name)
{
	return m_usetMacroEnableApps.find(StringUtil::ToLowerCase(app_name)) != m_usetMacroEnableApps.end();
}

EM_MarcoDetectResult MacroDetector::DetectMacro(const std::wstring& file_path, STRING_VECTOR& macro_contents)
{
	VbaParser vba_parser(ToolFunctions::WStringToString(file_path));
	vba_parser.ListVbaFiles(macro_contents);
	return vba_parser.isFileMalicious() ? EM_MarcoDetectResult::isMalicious : EM_MarcoDetectResult::NORMAL;
}
