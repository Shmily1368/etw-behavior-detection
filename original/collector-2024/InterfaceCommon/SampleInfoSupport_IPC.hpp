#pragma once
#include "NgepIpcClientApi.h"
#include "SampleInfoJsonHelper.h"
#include "MSTypeConversion.h"

class SampleInfoSupport_IPC
{
public:
	SampleInfoSupport_IPC(const std::wstring& strIpcSrc, const std::wstring& strDllPath) {
#ifdef NGEPIPCCLIENT_NO_USE_LIB
		m_pIpc = GetNgepIpcClientInstance(strIpcSrc, strDllPath);
#else
		m_pIpc = INgepIpcClientGetInstance(strIpcSrc.c_str(), strIpcSrc.length());
#endif // NGEPIPCCLIENT_NO_USE_LIB
	}
	~SampleInfoSupport_IPC() {}

	bool UploadSampleFile(Sample_Info* pInfo
		, BOOL bSaveSampleLog = FALSE, LPCTSTR lpEProcess = nullptr
		, DWORD dwPID = -1, LPCTSTR lpUser = nullptr)
	{
		if (pInfo->szMD5A[0] == '\0')
			return false;
		bool bRet = false;
		cJSON* pJsonRoot = cJSON_CreateObject();
		if (pJsonRoot == NULL)
			return bRet;
		SampleInfoJsonHelper::SampleInfo2Json(pInfo, pJsonRoot);
		cJSON_AddItemToObject(pJsonRoot, "SaveSampleLog", cJSON_CreateBool(bSaveSampleLog));
		if (bSaveSampleLog)
		{
			assert(lpEProcess != nullptr
				&& (dwPID != -1 || lpUser != nullptr));
			cJsonHelper::AddStringItem(pJsonRoot, "EProcess", lpEProcess);
			cJSON_AddItemToObject(pJsonRoot, "PID", cJSON_CreateNumber(dwPID));
			cJsonHelper::AddStringItem(pJsonRoot, "User", lpUser);
		}
		char* szTemp = cJSON_PrintUnformatted(pJsonRoot);
		std::string strT = szTemp;
		WriteLog4cPlusBaseA(DEBUG_LEVEL, "%s", strT.c_str());
		if (szTemp != NULL)
		{
			free(szTemp);
			szTemp = NULL;
		}
		std::string strEncryptTxt = CMSTypeConversion::XorAndBase64String(strT
			, SampleInfoJsonHelper::m_xor_Base64Key);
		bRet = (MS_ERROR_SUCCESS == m_pIpc->AddNgepUploadSample(strEncryptTxt.c_str(), (int)strEncryptTxt.length()
			, pInfo->szFilePathUtf8, (int)strlen(pInfo->szFilePathUtf8)
			, pInfo->szMD5Utf8, (int)strlen(pInfo->szMD5Utf8)));

		if (pJsonRoot != NULL)
		{
			cJSON_Delete(pJsonRoot); // 自动删除pArguments
			pJsonRoot = NULL;
		}
		return bRet;
	}
private:
	INgepIpcClient* m_pIpc = nullptr;
};