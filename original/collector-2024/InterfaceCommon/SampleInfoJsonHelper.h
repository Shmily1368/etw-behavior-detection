#pragma once
#include "SampleInfoDef.h"
//#include "../../ThirdPart/cJSON/include/cJsonHelper.hpp"

class SampleInfoJsonHelper
{
public:
	static constexpr unsigned char m_xor_Base64Key = 0x21;

	SampleInfoJsonHelper() {}
	~SampleInfoJsonHelper() {}

	static bool SampleInfo2Json(const Sample_Info* pInfo, cJSON* pJsonData)
	{
		cJSON_AddItemToObject(pJsonData, "SI_UUID", cJSON_CreateString(pInfo->szUUIDUtf8));
		cJSON_AddItemToObject(pJsonData, "SI_EventTime", cJSON_CreateString(pInfo->szEventTimeUtf8));
		cJSON_AddItemToObject(pJsonData, "SI_FileName", cJSON_CreateString(pInfo->szFileNameUtf8));
		cJSON_AddItemToObject(pJsonData, "SI_FilePath", cJSON_CreateString(pInfo->szFilePathUtf8));
		cJSON_AddItemToObject(pJsonData, "SI_MD5", cJSON_CreateString(pInfo->szMD5Utf8));
		cJSON_AddItemToObject(pJsonData, "SI_LogID", cJSON_CreateString(pInfo->szLogIDUtf8));
		cJSON_AddItemToObject(pJsonData, "SI_LogName", cJSON_CreateString(pInfo->szLogNameUtf8));
		cJSON_AddItemToObject(pJsonData, "SI_User", cJSON_CreateString(pInfo->szUserUtf8));
		cJSON_AddItemToObject(pJsonData, "SI_Size", cJSON_CreateString(pInfo->szSizeUtf8));
		return true;
	}

	static bool Json2SampleInfo(const cJSON* pJsonData, Sample_Info* pInfo)
	{
		std::string strData;
		if (cJsonHelper::GetJsonString(pJsonData, "SI_UUID", strData) && !strData.empty())
			pInfo->SetUUID_UTF8(strData.c_str());
		strData.clear();
		if (cJsonHelper::GetJsonString(pJsonData, "SI_EventTime", strData) && !strData.empty())
			pInfo->SetEventTime_UTF8(strData.c_str());
		strData.clear();
		if (cJsonHelper::GetJsonString(pJsonData, "SI_FileName", strData) && !strData.empty())
			pInfo->SetFileName_UTF8(strData.c_str());
		strData.clear();
		if (cJsonHelper::GetJsonString(pJsonData, "SI_FilePath", strData) && !strData.empty())
			pInfo->SetFilePath_UTF8(strData.c_str());
		strData.clear();
		if (cJsonHelper::GetJsonString(pJsonData, "SI_MD5", strData) && !strData.empty())
			pInfo->SetMd5_UTF8(strData.c_str());
		strData.clear();
		if (cJsonHelper::GetJsonString(pJsonData, "SI_LogID", strData) && !strData.empty())
			pInfo->SetLogId_UTF8(strData.c_str());
		strData.clear();
		if (cJsonHelper::GetJsonString(pJsonData, "SI_LogName", strData) && !strData.empty())
			pInfo->SetLogName_UTF8(strData.c_str());
		strData.clear();
		if (cJsonHelper::GetJsonString(pJsonData, "SI_User", strData) && !strData.empty())
			pInfo->SetUser_UTF8(strData.c_str());
		strData.clear();
		if (cJsonHelper::GetJsonString(pJsonData, "SI_Size", strData) && !strData.empty())
			pInfo->SetSize_UTF8(strData.c_str());
		return true;
	}
private:

};