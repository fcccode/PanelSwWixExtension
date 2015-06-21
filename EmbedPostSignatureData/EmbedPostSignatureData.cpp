// EmbedPostSignatureData.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
#using <mscorlib.dll>
using namespace System::IO;
using namespace System;

int _tmain(int argc, _TCHAR* argv[])
{
	return 0;
}

namespace PostSignatureTag
{
	class __declspec(dllexport) PostSignatureTag
	{
	public:
		static HRESULT ApplyTag(System::String^ signed_exe_file, String^ tag_string, String^ tagged_file, bool append)
		{
			HRESULT hr = S_OK;

			// Sanity check.
			if (System::String::IsNullOrEmpty(signed_exe_file))
			{
				throw gcnew System::ArgumentNullException("signed_exe_file is null/empty");
			}
			if (System::String::IsNullOrEmpty(tag_string))
			{
				throw gcnew System::ArgumentNullException("tag_string is null/empty");
			}
			if (System::String::IsNullOrEmpty(tagged_file))
			{
				throw gcnew System::ArgumentNullException("tagged_file is null/empty");
			}

			// Signed file exists?
			if (!File::Exists(signed_exe_file))
			{
				throw gcnew System::ArgumentNullException("signed_exe_file does not exist");
			}

			// Get (& create) target folder.
			String^ dir = Path::GetDirectoryName(tagged_file);
			Directory::CreateDirectory(dir);

			int tag_string_length = lstrlen(tag_string);
			omaha::ApplyTag tag;
			HRESULT hr = tag.Init(signed_exe_file,
			CT2CA(tag_string),
			tag_string_length,
			out_path,
			append);
			if (FAILED(hr))
			{
			return hr;
			}

			hr = tag.EmbedTagString();
			if (hr == APPLYTAG_E_ALREADY_TAGGED)
			{
			return HRESULT_FROM_WIN32(ERROR_FILE_EXISTS);
			}

		LExit:

			return hr;
		}
	};
}