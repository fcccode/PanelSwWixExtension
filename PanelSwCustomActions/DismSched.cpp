#include "stdafx.h"
#include <wcautil.h>
#include <strutil.h>
#include <list>
#include <string>
#include <Shlwapi.h>
#include "dismDetails.pb.h"
#include "DeferredActionBase.h"
#pragma comment (lib, "Shlwapi.lib")
using namespace std;
using namespace com::panelsw::ca;
using namespace google::protobuf;

#define Dism_QUERY L"SELECT `Id`, `Component_`, `EnableFeatures` FROM `PSW_Dism`"
enum DismQuery { Id = 1, Component = 2, EnableFeatures = 3 };

#define DismLogPrefix		L"DismLog="

// Immediate custom action
extern "C" UINT __stdcall DismSched(MSIHANDLE hInstall)
{
	UINT er = ERROR_SUCCESS;
	HRESULT hr = S_OK;
	BOOL bRes = TRUE;
	LPWSTR szMsiLog = nullptr;
	WCHAR szDismLog[MAX_PATH];
	PMSIHANDLE hView;
	PMSIHANDLE hRecord;
	LPWSTR szId = nullptr;
	LPWSTR szComponent = nullptr;
	LPWSTR szFeature = nullptr;
	LPWSTR szCAD = nullptr;
	int nVersionNT = 0;
	DismDetails details;

	hr = WcaInitialize(hInstall, __FUNCTION__);
	ExitOnFailure(hr, "Failed to initialize");
	WcaLog(LOGMSG_STANDARD, "Initialized from PanelSwCustomActions " FullVersion);

	hr = WcaGetIntProperty(L"VersionNT", &nVersionNT);
	ExitOnFailure(hr, "Failed to get VersionNT");

	// DISM log file
	hr = WcaGetProperty(L"MsiLogFileLocation", &szMsiLog);
	ExitOnFailure(hr, "Failed to get MsiLogFileLocation");

	// Are we logging?
	if (szMsiLog && (::wcslen(szMsiLog) <= (MAX_PATH - 6)))
	{
		::wcscpy_s(szDismLog, szMsiLog);

		bRes = ::PathRenameExtension(szDismLog, L".dism.log");
		ExitOnNullWithLastError1(bRes, hr, "Failed renaming file extension: '%ls'", szMsiLog);

		details.set_logfile(szDismLog, WSTR_BYTE_SIZE(szDismLog));
	}

	// Execute view
	hr = WcaOpenExecuteView(Dism_QUERY, &hView);
	ExitOnFailure(hr, "Failed to execute SQL query '%ls'.", Dism_QUERY);

	// Iterate records
	while ((hr = WcaFetchRecord(hView, &hRecord)) != E_NOMOREITEMS)
	{
		ExitOnFailure(hr, "Failed to fetch record.");

		// Get fields
		PMSIHANDLE hExitCodeView;
		PMSIHANDLE hExitCodeRecord;
		WCA_TODO compAction = WCA_TODO_UNKNOWN;
		DWORD_PTR szStrLen = 0;

		hr = WcaGetRecordString(hRecord, DismQuery::Id, &szId);
		ExitOnFailure(hr, "Failed to get Id.");
		hr = WcaGetRecordString(hRecord, DismQuery::Component, &szComponent);
		ExitOnFailure(hr, "Failed to get Component.");
		hr = WcaGetRecordFormattedString(hRecord, DismQuery::EnableFeatures, &szFeature);
		ExitOnFailure(hr, "Failed to get EnableFeatures.");

		compAction = WcaGetComponentToDo(szComponent);
		switch (compAction)
		{
		case WCA_TODO::WCA_TODO_INSTALL:
		case WCA_TODO::WCA_TODO_REINSTALL:
			WcaLog(LOGLEVEL::LOGMSG_STANDARD, "Will enable features matching pattern '%ls' on component '%ls'", szFeature, szComponent);

			if (nVersionNT <= 601)
			{
				ExitOnFailure(hr = E_NOTIMPL, "PanelSwWixExtension Dism is only supported on Windows 8 / Windows Server 2008 R2 or newer operating systems");
			}

			details.add_featureregexexpression(szFeature, WSTR_BYTE_SIZE(szFeature));
			break;

		case WCA_TODO::WCA_TODO_UNINSTALL:
		case WCA_TODO::WCA_TODO_UNKNOWN:
			WcaLog(LOGLEVEL::LOGMSG_STANDARD, "Skipping DISM for feature '%ls' as component '%ls' is not installed or repaired", szId, szComponent);
			break;
		}

		// Clean for next iteration
		ReleaseNullStr(szId);
		ReleaseNullStr(szComponent);
		ReleaseNullStr(szFeature);
	}
	hr = S_OK; // We're only getting here on hr = E_NOMOREITEMS.

	// Since Dism API takes long, we only want to execute it if there's something to do. Conditioning the Dism deferred CA with the property existance will save us time.
	if (details.featureregexexpression_size())
	{
		std::string srlz;

		bRes = details.SerializeToString(&srlz);
		BreakExitOnNull(bRes, hr, E_FAIL, "Failed serializing CustomActionData");

		hr = StrAllocBase85Encode((const BYTE*)srlz.data(), srlz.size(), &szCAD);
		BreakExitOnFailure(hr, "Failed encode CustomActionData");

		hr = WcaSetProperty(L"DismX86", szCAD);
		ExitOnFailure(hr, "Failed setting CustomActionData");

		hr = WcaSetProperty(L"DismX64", szCAD);
		ExitOnFailure(hr, "Failed setting CustomActionData");
	}

LExit:
	ReleaseStr(szMsiLog);
	ReleaseStr(szCAD);
	ReleaseStr(szId);
	ReleaseStr(szComponent);
	ReleaseStr(szFeature);

	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}
