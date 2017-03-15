// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

//#include <windows.h>
//#include <tchar.h>

#include <iostream>
using std::cin;
using std::wcin;
using std::cout;
using std::wcout;
using std::cerr;
using std::wcerr;
using std::endl;

#include <string>
using std::string;
using std::wstring;

#ifdef UNICODE
#  define tcin wcin
#  define tcout wcout
#  define tcerr wcerr
#  define tstring wstring
#else
#  define tcin cin
#  define tcout cout
#  define tcerr cerr
#  define tstring string
#endif

