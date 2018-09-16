#pragma once
#include "../CaCommon/DeferredActionBase.h"
#include <map>

class CExecOnComponent :
	public CDeferredActionBase
{
public:
    typedef std::map<int, int> ExitCodeMap;
    typedef std::map<int, int>::const_iterator ExitCodeMapItr;

	HRESULT AddExec(LPCWSTR szCommand, LPCWSTR szObfuscatedCommand, ExitCodeMap *pExitCodeMap, int nFlags);

protected:
	// Execute the command object (XML element)
	HRESULT DeferredExecute(const ::std::string& command) override;
};

