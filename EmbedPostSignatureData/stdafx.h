// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"
#include <Windows.h>
#include <WinError.h>
#include <TCHAR.h>

#include <stdio.h>

#define PrintAndExit( s, ...)					\
		{										\
			printf(s, __VA_ARGS__);				\
			goto LExit;							\
		}


#define ExitOnZero( p, eHr, s, ...)				\
			if (p == NULL)						\
			{									\
				hr = eHr;						\
				PrintAndExit(s, __VA_ARGS__);	\
			}

#define ExitOnFailure( s, ...)					if( FAILED(hr)) { PrintAndExit( s, __VA_ARGS__); }


// TODO: reference additional headers your program requires here
