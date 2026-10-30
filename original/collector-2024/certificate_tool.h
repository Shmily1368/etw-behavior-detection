#pragma once
#include <unordered_map>
#include <Windows.h>
#include "publicstruct.h"

class CertificateTool
{
public:
	//static bool VerifyEmbeddedSignature(LPCWSTR file_name);
	static EM_CertificateResult VerifyEmbeddedSignature(LPCWSTR file_name);
	static size_t CertificateCacheSize() { return _certificate_cache_map.size(); }
    static int GetCertificateResult(LPCWSTR file_name);
private:
    static int GetCertificateThumbPrint(LPCWSTR file_name, std::string &thumbPrint);
	static bool GetFileDescription(std::wstring file_name, std::wstring &fileDescription);
private:
	static EM_CertificateResult VerifySignature(LPCWSTR file_name);
	static BOOL CertificateTool::IsWhite(_In_ CONST std::wstring& wstrPath, _In_ CONST std::wstring& wstrDescription);
	static std::unordered_map<std::wstring, SCertificateResult> _certificate_cache_map;
    static RwLock _certificate_cache_lock;
	static std::wstring _protected_certificate;   //存放文件说明
	static std::unordered_set<std::wstring> _protected_certificate_cache;
	static std::unordered_set<std::wstring> _unprotected_certificate_cache;
	static bool _update_certificate_root; //如果证书根未更新，则将其更新
};

