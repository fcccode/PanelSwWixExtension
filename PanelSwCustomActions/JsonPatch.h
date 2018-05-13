#pragma once
#include "../CaCommon/DeferredActionBase.h"

class CJsonPatch :
	public CDeferredActionBase
{
public:

	HRESULT AddPatch(LPCWSTR szFile, LPCWSTR szPatch);

protected:
	// Execute the command object (XML element)
	HRESULT DeferredExecute(const ::std::string& command) override;

private:
	HRESULT Execute(LPCWSTR szFile, LPCWSTR szPatch);

	HRESULT ExecuteMultibyte(LPCWSTR szFilePath, LPCSTR szFileContent, LPCWSTR szPatch);
	HRESULT ExecuteUnicode(LPCWSTR szFilePath, LPCWSTR szFileContent, LPCWSTR szPatch);
};

