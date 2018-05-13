#include "JsonPatch.h"
#include "jsonPatchDetails.pb.h"
#include "../CaCommon/WixString.h"
#include "FileOperations.h"
#include "FileRegex.h"
#include <memutil.h>
#include "../json/single_include/nlohmann/json.hpp"
using namespace ::com::panelsw::ca;
using namespace google::protobuf;
using json = nlohmann::json;

#define CJsonPatch_QUERY L"SELECT `PSW_JsonPatch`.`Id`, `PSW_JsonPatch`.`File_`, `File`.`Component_`, `PSW_JsonPatch`.`Patch` FROM `PSW_JsonPatch`, `File` WHERE `File`.`File` = `PSW_JsonPatch`.`File_`"
enum CJsonPatchQuery { Id = 1, File_ = 2, Component_ = 3, Patch = 4 };

extern "C" UINT __stdcall JsonPatch(MSIHANDLE hInstall)
{
	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;
	DWORD dwRes = ERROR_SUCCESS;
	PMSIHANDLE hView;
	PMSIHANDLE hRecord;
	CJsonPatch deferredCAD;
	CFileOperations deferredFileCAD;
	CFileOperations rollbackCAD;
	CFileOperations commitCAD;
	LPWSTR szCustomActionData = nullptr;
	WCHAR szTempFolder[MAX_PATH + 1];

	hr = WcaInitialize(hInstall, __FUNCTION__);
	BreakExitOnFailure(hr, "Failed to initialize");
	WcaLog(LOGMSG_STANDARD, "Initialized from PanelSwCustomActions " FullVersion);

	dwRes = ::GetTempPath(MAX_PATH, szTempFolder);
	BreakExitOnNullWithLastError(dwRes, hr, "Failed getting temporary folder");
	BreakExitOnNull((dwRes <= MAX_PATH), hr, E_FAIL, "Temporary folder path too long");

	// Ensure table PSW_ShellExecute exists.
	hr = WcaTableExists(L"PSW_JsonPatch");
	BreakExitOnFailure(hr, "Table does not exist 'PSW_JsonPatch'. Have you authored 'PanelSw:JsonPatch' entries in WiX code?");

	// Execute view
	hr = WcaOpenExecuteView(CJsonPatch_QUERY, &hView);
	BreakExitOnFailure(hr, "Failed to execute SQL query '%ls'.", CJsonPatch_QUERY);

	// Iterate records
	while ((hr = WcaFetchRecord(hView, &hRecord)) != E_NOMOREITEMS)
	{
		BreakExitOnFailure(hr, "Failed to fetch record.");

		// Get fields
		CWixString szId, szFile, szCompnent, szPatch;
		CWixString szFileFmt, szFilePath;
		WCA_TODO compTodo = WCA_TODO::WCA_TODO_UNKNOWN;
		WCHAR szTempFile[MAX_PATH + 1];

		hr = WcaGetRecordString(hRecord, CJsonPatchQuery::Id, (LPWSTR*)szId);
		BreakExitOnFailure(hr, "Failed to get Id.");
		hr = WcaGetRecordFormattedString(hRecord, CJsonPatchQuery::File_, (LPWSTR*)szFile);
		BreakExitOnFailure(hr, "Failed to get Target.");
		hr = WcaGetRecordFormattedString(hRecord, CJsonPatchQuery::Component_, (LPWSTR*)szCompnent);
		BreakExitOnFailure(hr, "Failed to get Args.");
		hr = WcaGetRecordFormattedString(hRecord, CJsonPatchQuery::Patch, (LPWSTR*)szPatch);
		BreakExitOnFailure(hr, "Failed to get Verb.");

		compTodo = WcaGetComponentToDo(szCompnent);
		switch (compTodo)
		{
		case WCA_TODO::WCA_TODO_INSTALL:
		case WCA_TODO::WCA_TODO_REINSTALL:
			WcaLog(LOGMSG_STANDARD, "Will patch file '%ls'", (LPCWSTR)szFile);
			break;

		case WCA_TODO::WCA_TODO_UNINSTALL:
		case WCA_TODO::WCA_TODO_UNKNOWN:
			WcaLog(LOGMSG_STANDARD, "Skip json-patch of file '%ls' as componet is not (re)installed", (LPCWSTR)szFile);
			continue;

		default:
			hr = E_FAIL;
			BreakExitOnFailure(hr, "Bad Component todo");
		}

		hr = szFileFmt.Format(L"[#%s]", (LPCWSTR)szFile);
		BreakExitOnFailure(hr, "Failed formatting string");

		hr = szFilePath.MsiFormat(szFileFmt);
		BreakExitOnFailure(hr, "Failed msi-formatting string");

		dwRes = ::GetTempFileName(szTempFolder, L"JSP", 0, szTempFile);
		BreakExitOnNullWithLastError(dwRes, hr, "Failed getting temporary file name");

		hr = deferredFileCAD.AddCopyFile(szFilePath, szTempFile);
		BreakExitOnFailure(hr, "Failed scheduling file copy");

		hr = deferredCAD.AddPatch(szFilePath, szPatch);
		BreakExitOnFailure(hr, "Failed scheduling JSON file patch");

		hr = rollbackCAD.AddMoveFile(szTempFile, szFilePath);
		BreakExitOnFailure(hr, "Failed scheduling file move");

		hr = commitCAD.AddDeleteFile(szTempFile);
		BreakExitOnFailure(hr, "Failed scheduling file delete");
	}
	
	// Schedule actions.
	hr = rollbackCAD.GetCustomActionData(&szCustomActionData);
	BreakExitOnFailure(hr, "Failed getting custom action data for rollback action.");
	hr = WcaDoDeferredAction(L"JsonPatch_rollback", szCustomActionData, rollbackCAD.GetCost());
	BreakExitOnFailure(hr, "Failed scheduling rollback action.");

	ReleaseNullStr(szCustomActionData);
	hr = deferredCAD.Prepend(&deferredFileCAD);
	BreakExitOnFailure(hr, "Failed prepending custom action data for deferred action.");
	hr = deferredCAD.GetCustomActionData(&szCustomActionData);
	BreakExitOnFailure(hr, "Failed getting custom action data for deferred action.");
	hr = WcaDoDeferredAction(L"JsonPatch_deferred", szCustomActionData, deferredCAD.GetCost());
	BreakExitOnFailure(hr, "Failed scheduling deferred action.");

	ReleaseNullStr(szCustomActionData);
	hr = commitCAD.GetCustomActionData(&szCustomActionData);
	BreakExitOnFailure(hr, "Failed getting custom action data for commit action.");
	hr = WcaDoDeferredAction(L"JsonPatch_commit", szCustomActionData, commitCAD.GetCost());
	BreakExitOnFailure(hr, "Failed scheduling commit action.");

LExit:
	ReleaseStr(szCustomActionData);
	
	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}

HRESULT CJsonPatch::AddPatch(LPCWSTR szFile, LPCWSTR szPatch)
{
	HRESULT hr = S_OK;
	::com::panelsw::ca::Command *pCmd = nullptr;
	JsonPatchDetails *pDetails = nullptr;
	::std::string *pAny = nullptr;
	bool bRes = true;

	hr = AddCommand("CJsonPatch", &pCmd);
	BreakExitOnFailure(hr, "Failed to add command");

	pDetails = new JsonPatchDetails();
	BreakExitOnNull(pDetails, hr, E_FAIL, "Failed allocating details");

	pDetails->set_file(szFile, WSTR_BYTE_SIZE(szFile));
	pDetails->set_patch(szPatch, WSTR_BYTE_SIZE(szPatch));

	pAny = pCmd->mutable_details();
	BreakExitOnNull(pAny, hr, E_FAIL, "Failed allocating any");

	bRes = pDetails->SerializeToString(pAny);
	BreakExitOnNull(bRes, hr, E_FAIL, "Failed serializing command details");

LExit:
	return hr;
}

// Execute the command object (XML element)
HRESULT CJsonPatch::DeferredExecute(const ::std::string& command)
{
	HRESULT hr = S_OK;
	BOOL bRes = TRUE;
	JsonPatchDetails details;
	LPCWSTR szFile = nullptr;
	LPCWSTR szPatch = nullptr;

	bRes = details.ParseFromString(command);
	BreakExitOnNull(bRes, hr, E_INVALIDARG, "Failed unpacking ShellExecDetails");

	szFile = (LPCWSTR)details.file().data();
	szPatch = (LPCWSTR)details.patch().data();

	hr = Execute(szFile, szPatch);
	BreakExitOnFailure(hr, "Failed json-patch file '%ls'", szFile);

LExit:
	return hr;
}

HRESULT CJsonPatch::Execute(LPCWSTR szFile, LPCWSTR szPatch)
{
    HRESULT hr = S_OK;
	DWORD dwBytesRead = 0;
	DWORD dwFileSize = 0;
	BOOL bRes = TRUE;
	void* pFileContents = nullptr;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	FileRegexDetails::FileEncoding encoding = FileRegexDetails::FileEncoding::FileRegexDetails_FileEncoding_None;

	::MessageBox(NULL, __FUNCTIONW__, __FUNCTIONW__, MB_OK);
	WcaLog(LOGLEVEL::LOGMSG_STANDARD, "Json-patch on file '%ls'", szFile);

	hFile = ::CreateFile(szFile, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	ExitOnNullWithLastError((hFile != INVALID_HANDLE_VALUE), hr, "Failed opening file");

	dwFileSize = ::GetFileSize(hFile, nullptr);
	pFileContents = MemAlloc(dwFileSize + 2, FALSE);
	ExitOnNull(pFileContents, hr, E_FAIL, "Failed allocating memory");

	// Terminate with ascii/wchar NULL.
	((BYTE*)pFileContents)[dwFileSize] = NULL;
	((BYTE*)pFileContents)[dwFileSize + 1] = NULL;

	bRes = ::ReadFile(hFile, pFileContents, dwFileSize, &dwBytesRead, nullptr);
	ExitOnNullWithLastError(bRes, hr, "Failed reading file");
	ExitOnNull((dwFileSize == dwBytesRead), hr, E_FAIL, "Failed reading file. Read %i/%i bytes", dwBytesRead, dwFileSize);

	::CloseHandle(hFile);
	hFile = INVALID_HANDLE_VALUE;

	encoding = CFileRegex::DetectEncoding(pFileContents, dwFileSize);
	switch (encoding)
	{
	case FileRegexDetails::FileEncoding::FileRegexDetails_FileEncoding_MultiByte:
		hr = ExecuteMultibyte(szFile, (LPCSTR)pFileContents, szPatch);
		BreakExitOnFailure(hr, "Failed patching JSON file '%ls'", szFile);
		break;

	case FileRegexDetails::FileEncoding::FileRegexDetails_FileEncoding_Unicode:
		hr = ExecuteUnicode(szFile, (LPCWSTR)pFileContents, szPatch);
		BreakExitOnFailure(hr, "Failed patching JSON file '%ls'", szFile);
		break;

	case FileRegexDetails::FileEncoding::FileRegexDetails_FileEncoding_None:
	case FileRegexDetails::FileEncoding::FileRegexDetails_FileEncoding_ReverseUnicode:
	default:
		hr = E_NOTIMPL;
		BreakExitOnFailure(hr, "Not supported encoding %i", encoding);
		break;
	}

LExit:
	if (hFile != INVALID_HANDLE_VALUE)
	{
		::CloseHandle(hFile);
	}
	if (pFileContents)
	{
		MemFree(pFileContents);
	}

    return hr;
}


HRESULT CJsonPatch::ExecuteMultibyte(LPCWSTR szFilePath, LPCSTR szFileContent, LPCWSTR szPatch)
{
	HRESULT hr = S_OK;
	BOOL bRes = TRUE;
	DWORD dwSize = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	LPSTR szPatchMB = nullptr;
	DWORD dwBytesWritten = 0;
	DWORD dwFileAttr = FILE_ATTRIBUTE_NORMAL;

	// Convert szPatch to multi-byte.
	dwSize = ::WideCharToMultiByte(CP_UTF8, 0, szPatch, -1, nullptr, 0, nullptr, nullptr);
	ExitOnNullWithLastError(dwSize, hr, "Failed converting WCHAR string to multi-byte");

	szPatchMB = (LPSTR)MemAlloc(dwSize, FALSE);
	ExitOnNullWithLastError(szPatchMB, hr, "Failed allocating memory");

	dwSize = ::WideCharToMultiByte(CP_UTF8, 0, szPatch, -1, szPatchMB, dwSize, nullptr, nullptr);
	ExitOnNullWithLastError(dwSize, hr, "Failed converting WCHAR string to multi-byte");

	try
	{
		json j = json::to_json(std::string(szFileContent+3));
		json ptch = json::to_ubjson(std::string(szPatchMB));
		j.merge_patch(ptch);
		std::string srlz = j;

		dwFileAttr = ::GetFileAttributes(szFilePath);

		hFile = ::CreateFile(szFilePath, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, dwFileAttr, nullptr);
		ExitOnNullWithLastError((hFile != INVALID_HANDLE_VALUE), hr, "Failed creating file");

		bRes = ::WriteFile(hFile, srlz.c_str(), srlz.size(), &dwBytesWritten, nullptr);
		ExitOnNullWithLastError(bRes, hr, "Failed writing file");
		ExitOnNull((srlz.size() == dwBytesWritten), hr, E_FAIL, "Failed writing file. Wrote %i/%i bytes", dwBytesWritten, srlz.size());
	}
	catch (std::exception ex)
	{
		hr = E_FAIL;
		ExitOnFailure(hr, "Exception when patching json file '%ls': %s", szFilePath, ex.what());
	}
	catch(...)
	{
		hr = E_FAIL;
		ExitOnFailure(hr, "Exception when patching json file '%ls'", szFilePath);
	}

LExit:
	if (hFile != INVALID_HANDLE_VALUE)
	{
		::CloseHandle(hFile);
	}
	if (szPatchMB)
	{
		MemFree(szPatchMB);
	}

	return hr;
}

HRESULT CJsonPatch::ExecuteUnicode(LPCWSTR szFilePath, LPCWSTR szFileContent, LPCWSTR szPatch)
{
	HRESULT hr = S_OK;
	BOOL bRes = TRUE;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwSize = 0;
	DWORD dwBytesWritten = 0;
	DWORD dwFileAttr = FILE_ATTRIBUTE_NORMAL;

	try
	{
		json j = json::to_ubjson(std::wstring(szFileContent));
		json ptch = json::to_ubjson(std::wstring(szPatch));
		j.merge_patch(ptch);
		std::wstring srlz = j;

		dwSize = srlz.size() * sizeof(WCHAR);
		dwFileAttr = ::GetFileAttributes(szFilePath);

		hFile = ::CreateFile(szFilePath, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, dwFileAttr, nullptr);
		ExitOnNullWithLastError((hFile != INVALID_HANDLE_VALUE), hr, "Failed creating file");

		bRes = ::WriteFile(hFile, srlz.c_str(), dwSize, &dwBytesWritten, nullptr);
		ExitOnNullWithLastError(bRes, hr, "Failed writing file");
		ExitOnNull((dwSize == dwBytesWritten), hr, E_FAIL, "Failed writing file. Wrote %i/%i bytes", dwBytesWritten, dwSize);
	}
	catch (std::exception ex)
	{
		hr = E_FAIL;
		ExitOnFailure(hr, "Exception when patching json file '%ls': %s", szFilePath, ex.what());
	}
	catch (...)
	{
		hr = E_FAIL;
		ExitOnFailure(hr, "Exception when patching json file '%ls'", szFilePath);
	}

LExit:
	if (hFile != INVALID_HANDLE_VALUE)
	{
		::CloseHandle(hFile);
	}

	return hr;
}
