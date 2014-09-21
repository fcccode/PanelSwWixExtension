#include "stdafx.h"
#include "RegistryKey.h"
#include <strutil.h>

CRegistryKey::CRegistryKey(void)
	: _hKey( NULL)
	, _hRootKey( NULL)
	, _area( RegArea::Default)
	, _samAccess( RegAccess::All)
{	
	Close();
}

CRegistryKey::~CRegistryKey(void)
{
	Close();
}

HRESULT CRegistryKey::Close()
{
	HRESULT hr = S_OK;

	_hRootKey = NULL;
	::memset( _keyName, 0, sizeof( WCHAR) * MAX_PATH);

	if(( _hKey != NULL)
		&& ( _hKey != HKEY_CLASSES_ROOT)
		&& ( _hKey != HKEY_CURRENT_USER)
		&& ( _hKey != HKEY_LOCAL_MACHINE)
		&& ( _hKey != HKEY_CURRENT_CONFIG)
		&& ( _hKey != HKEY_USERS)
		)
	{
		LONG lRes = ::RegCloseKey( _hKey);
		hr = HRESULT_FROM_WIN32( lRes);
		_hKey = NULL;
	}

	return hr;
}

HRESULT CRegistryKey::Create( RegRoot root, WCHAR* key, RegArea area, RegAccess access)
{
	HRESULT hr = S_OK;
	HKEY hKey = NULL, hParentKey = NULL;
	LONG lRes;


	hr = Close();
	ExitOnFailure( hr, "Failed to close registry key");

	ExitOnNull( key, hr, E_FILENOTFOUND, "key is NULL");
	ExitOnNull( *key, hr, E_FILENOTFOUND, "key points to NULL");
	WcaLog( LOGLEVEL::LOGMSG_STANDARD, "Attempting to create registry key %ls", key);

	hParentKey = Root2Handle( root);
	ExitOnNull( hParentKey, hr, E_FILENOTFOUND, "key is NULL");

	_samAccess = access;
	_area = area;
	if( _area == RegArea::Default)
	{
		hr = GetDefaultArea( &_area);
		ExitOnFailure( hr, "Failed to get default registry area");
	}

	lRes = ::RegCreateKeyExW( hParentKey, key, 0, NULL, 0, _samAccess | _area, NULL, &hKey, NULL);
	hr = HRESULT_FROM_WIN32( lRes);
	ExitOnFailure( hr, "Failed to create registry key");

	_hKey = hKey;
	_hRootKey = hParentKey;
	wcscpy_s<MAX_PATH>( _keyName, key);

LExit:
	return hr;
}

HRESULT CRegistryKey::Open( RegRoot root, WCHAR* key, RegArea area, RegAccess access)
{
	HRESULT hr = S_OK;
	HKEY hKey = NULL, hParentKey = NULL;
	LONG lRes;

	ExitOnNull( key, hr, E_INVALIDARG, "key is NULL");

	hr = Close();
	ExitOnFailure( hr, "Failed to close registry key");

	hParentKey = Root2Handle( root);
	ExitOnNull( hParentKey, hr, E_INVALIDARG, "Parent key is NULL");

	WcaLog( LOGLEVEL::LOGMSG_STANDARD, "Attempting to open registry key %ls", key);

	_samAccess = access;
	_area = area;
	if( _area == RegArea::Default)
	{
		hr = GetDefaultArea( &_area);
		ExitOnFailure( hr, "Failed to get default registry area");
	}

	lRes = ::RegOpenKeyExW( hParentKey, key, 0, _samAccess | _area, &hKey);
	hr = HRESULT_FROM_WIN32( lRes);
	ExitOnFailure( hr, "Failed to open registry key");

	_hKey = hKey;
	_hRootKey = hParentKey;
	wcscpy_s<MAX_PATH>( _keyName, key);

LExit:
	return hr;
}

HRESULT CRegistryKey::Delete()
{
	HRESULT hr = S_OK;
	LONG lRes = ERROR_SUCCESS;
	WCHAR keyName[ MAX_PATH];

	ExitOnNull( _hKey, hr, E_FILENOTFOUND, "_hKey is NULL");
	
	// Copy info
	HKEY rootKey = _hRootKey;
	wcscpy_s<MAX_PATH>( keyName, _keyName);

	// Close held handle.
	Close();

	// Delete key
	lRes = ::RegDeleteKeyExW( rootKey, keyName, _area, 0);
	hr = HRESULT_FROM_WIN32( lRes);
	ExitOnFailure( hr, "Failed to delete registry key");

LExit:
	return hr;
}

HRESULT CRegistryKey::GetValue( WCHAR* name, BYTE** pData, RegValueType* pType, DWORD* pDataSize)
{
	LONG lRes = ERROR_SUCCESS;
	HRESULT hr = S_OK;

	ExitOnNull( pData, hr, E_INVALIDARG, "pData is NULL");
	ExitOnNull( pType, hr, E_INVALIDARG, "pType is NULL");
	ExitOnNull( pDataSize, hr, E_INVALIDARG, "pDataSize is NULL");

	(*pDataSize) = 0;
	lRes = ::RegQueryValueEx( _hKey, name, 0, (LPDWORD)pType, NULL, pDataSize);
	hr = HRESULT_FROM_WIN32( lRes);
	ExitOnFailure( hr, "Failed to query registry value");
	ExitOnNull( (*pDataSize), hr, E_FILENOTFOUND, "Registry value's size is 0.");

	(*pData) = new BYTE[ (*pDataSize) + 1];
	ExitOnNull( (*pData), hr, E_NOT_SUFFICIENT_BUFFER, "Can't allocate buffer");

	lRes = ::RegQueryValueEx( _hKey, name, 0, (LPDWORD)pType, (*pData), pDataSize);
	hr = HRESULT_FROM_WIN32( lRes);
	ExitOnFailure( hr, "Failed to get registry value");
	(*pData)[ (*pDataSize)] = NULL; // Just to make sure.

LExit:
	return hr;
}

HRESULT CRegistryKey::SetValue( WCHAR* name, RegValueType type, BYTE* value, DWORD valueSize)
{
	HRESULT hr = S_OK;
	LONG lRes = ERROR_SUCCESS;
	ExitOnNull( _hKey, hr, E_FILENOTFOUND, "_hKey is NULL");

	lRes = ::RegSetValueEx( _hKey, name, 0, type, value, valueSize);
	hr = HRESULT_FROM_WIN32( lRes);
	ExitOnFailure( hr, "Failed to set registry value");

LExit:
	return hr;
}

HRESULT CRegistryKey::SetValueString( WCHAR* name, WCHAR* value)
{
	HRESULT hr = S_OK;

	ExitOnNull( name, hr, E_FILENOTFOUND, "name is NULL");
	ExitOnNull( value, hr, E_FILENOTFOUND, "value is NULL");

	DWORD dwSize = ((wcslen( value) + 1) * sizeof( WCHAR));
	hr = SetValue(
		name
		, RegValueType::String
		, (BYTE*)value
		, dwSize
		);

LExit:
	return hr;
}

HRESULT CRegistryKey::DeleteValue( WCHAR* name)
{
	HRESULT hr = S_OK;
	LONG lRes = ERROR_SUCCESS;
	ExitOnNull( _hKey, hr, E_FILENOTFOUND, "_hKey is NULL");

	RegDeleteValue( _hKey, name);

LExit:
	return hr;
}

HKEY CRegistryKey::Root2Handle( RegRoot root)
{
	switch( root)
	{
	case RegRoot::ClassesRoot:
		return HKEY_CLASSES_ROOT;

	case RegRoot::LocalMachine:
		return HKEY_LOCAL_MACHINE;

	case RegRoot::CurrentUser:
		return HKEY_CURRENT_USER;

	case RegRoot::CurrentConfig:
		return HKEY_CURRENT_CONFIG;

	case RegRoot::PerformanceData:
		return HKEY_PERFORMANCE_DATA;

	case RegRoot::Users:
		return HKEY_USERS;
	}

	return NULL;
}

HRESULT CRegistryKey::ParseRoot( LPCWSTR pRootString, RegRoot* peRoot)
{
	HRESULT hr = S_OK;

	ExitOnNull( peRoot, hr, E_INVALIDARG, "Invalid root pointer");
	
	if(( pRootString == NULL) || ( wcslen( pRootString) == 0))
	{
		(*peRoot) = RegRoot::CurrentUser;
		ExitFunction();
	}

	if(( _wcsicmp( pRootString, L"HKLM") == 0)
		|| ( _wcsicmp( pRootString, L"HKEY_LOCAL_MACHINE") == 0))
	{
		(*peRoot) = RegRoot::LocalMachine;
	}
	else if(( _wcsicmp( pRootString, L"HKCR") == 0)
		|| ( _wcsicmp( pRootString, L"HKEY_CLASSES_ROOT") == 0))
	{
		(*peRoot) = RegRoot::ClassesRoot;
	}
	else if(( _wcsicmp( pRootString, L"HKCC") == 0)
		|| ( _wcsicmp( pRootString, L"HKEY_CURRENT_CONFIG") == 0))
	{
		(*peRoot) = RegRoot::CurrentConfig;
	}
	else if(( _wcsicmp( pRootString, L"HKCU") == 0)
		|| ( _wcsicmp( pRootString, L"HKEY_CURRENT_USER") == 0))
	{
		(*peRoot) = RegRoot::CurrentUser;
	}
	else if(( _wcsicmp( pRootString, L"HKU") == 0)
		|| ( _wcsicmp( pRootString, L"HKEY_USERS") == 0))
	{
		(*peRoot) = RegRoot::Users;
	}
	else
	{
		hr = E_INVALIDARG;
		ExitOnFailure( hr, "Invalid root name");
	}

LExit:
	return hr;
}

HRESULT CRegistryKey::ParseArea( LPCWSTR pAreaString, RegArea* peArea)
{
	HRESULT hr = S_OK;

	ExitOnNull( peArea, hr, E_INVALIDARG, "Invalid area pointer");

	if(( pAreaString == NULL) || ((*pAreaString) == NULL) || ( _wcsicmp( pAreaString, L"default") == 0))
	{
		hr = GetDefaultArea( peArea);
		ExitOnFailure( hr, "Failed to get default registry area");
		ExitFunction();
	}
	else if( _wcsicmp( pAreaString, L"x86") == 0)
	{
		(*peArea) = RegArea::X86;
	}
	else if( _wcsicmp( pAreaString, L"x64") == 0)
	{
		(*peArea) = RegArea::X64;
	}
	else
	{
		hr = E_INVALIDARG;
		ExitOnFailure( hr, "Invalid area name");
	}

LExit:
	return hr;
}

HRESULT CRegistryKey::ParseValueType(LPCWSTR pTypeString, RegValueType* peType)
{
	HRESULT hr = S_OK;

	ExitOnNull(peType, hr, E_INVALIDARG, "Invalid type pointer");

	if ((pTypeString == NULL) || (wcslen(pTypeString) == 0))
	{
		(*peType) = RegValueType::String;
		ExitFunction();
	}

	if ((_wcsicmp(pTypeString, L"REG_SZ") == 0)
		|| (_wcsicmp(pTypeString, L"String") == 0)
		|| (_wcsicmp(pTypeString, L"1") == 0))
	{
		(*peType) = RegValueType::String;
	}
	else if ((_wcsicmp(pTypeString, L"REG_BINARY") == 0)
		|| (_wcsicmp(pTypeString, L"Binary") == 0)
		|| (_wcsicmp(pTypeString, L"3") == 0))
	{
		(*peType) = RegValueType::Binary;
	}
	else if ((_wcsicmp(pTypeString, L"REG_DWORD") == 0)
		|| (_wcsicmp(pTypeString, L"DWord") == 0)
		|| (_wcsicmp(pTypeString, L"4") == 0))
	{
		(*peType) = RegValueType::DWord;
	}
	else if ((_wcsicmp(pTypeString, L"REG_EXPAND_SZ") == 0)
		|| (_wcsicmp(pTypeString, L"Expandable") == 0)
		|| (_wcsicmp(pTypeString, L"2") == 0))
	{
		(*peType) = RegValueType::Expandable;
	}
	else if ((_wcsicmp(pTypeString, L"REG_MULTI_SZ") == 0)
		|| (_wcsicmp(pTypeString, L"MultiString") == 0)
		|| (_wcsicmp(pTypeString, L"7") == 0))
	{
		(*peType) = RegValueType::MultiString;
	}
	else if ((_wcsicmp(pTypeString, L"REG_QWORD") == 0)
		|| (_wcsicmp(pTypeString, L"QWord") == 0)
		|| (_wcsicmp(pTypeString, L"11") == 0))
	{
		(*peType) = RegValueType::QWord;
	}
	else
	{
		hr = E_INVALIDARG;
		ExitOnFailure(hr, "Invalid area name");
	}

LExit:
	return hr;
}

HRESULT CRegistryKey::GetDefaultArea( CRegistryKey::RegArea* pArea)
{
	HRESULT hr = S_OK;
	DWORD dwRes = ERROR_SUCCESS;
	MSIHANDLE hDatabase = NULL;
	PMSIHANDLE hSummaryInfo;
	UINT uiDataType = 0;
	DWORD dwDataSize = 0;
	WCHAR *pTemplate = NULL;
	FILETIME ftJunk;
	INT iJunk;

	ExitOnNull( pArea, hr, E_INVALIDARG, "pArea is NULL");
	(*pArea) = RegArea::Default;

	::MessageBox( NULL, L"MsiBreak", L"MsiBreak", MB_OK);

	hDatabase = WcaGetDatabaseHandle();
	ExitOnNull( hDatabase, hr, E_FAIL, "Failed to get MSI database");

	dwRes = ::MsiGetSummaryInformation( hDatabase, NULL, 0, &hSummaryInfo);
	hr = HRESULT_FROM_WIN32( dwRes);
	ExitOnFailure( hr, "Failed to get summary stream");

	dwRes = ::MsiSummaryInfoGetProperty( hSummaryInfo, 7 /*PID_TEMPLATE*/ , &uiDataType, &iJunk, &ftJunk, L"", &dwDataSize);
	if( dwRes != ERROR_MORE_DATA)
	{
		hr = E_INVALIDSTATE;
		ExitOnFailure( hr, "Failed getting MSI Template property size from summary stream");
	}

	++dwDataSize;
	hr = StrAlloc( &pTemplate, dwDataSize);
	ExitOnFailure( hr, "Failed to allocate memory");
	
	dwRes = ::MsiSummaryInfoGetProperty( hSummaryInfo, 7 /*PID_TEMPLATE*/ , &uiDataType, &iJunk, &ftJunk, pTemplate, &dwDataSize);
	hr = HRESULT_FROM_WIN32( dwRes);
	ExitOnFailure( hr, "Failed to get summary stream template property");

	if(( ::wcsstr( pTemplate, L"Intel64") != NULL) || ( ::wcsstr( pTemplate, L"x64") != NULL))
	{
		(*pArea) = RegArea::X64;
	}
	else
	{
		(*pArea) = RegArea::X86;
	}

LExit:

	if( pTemplate != NULL)
	{
		StrFree( pTemplate);
		pTemplate = NULL;
	}

	return hr;
}