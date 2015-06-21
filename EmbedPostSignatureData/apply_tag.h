#pragma once

#include <vcclr.h>
#using <mscorlib.dll>
using namespace System::IO;
using namespace System;

namespace PostSignatureTag
{
	class ApplyTag {
	public:
		ApplyTag();
		
		void Init(String^ signed_exe_file, String^ tag_string, int tag_string_length, String^ tagged_file, bool append);
		
		void EmbedTagString();

	private:
		static unsigned GetUint32(const void* p);
		static void PutUint32(unsigned i, void* p);
		bool ReadExistingTag(array<unsigned char>^ binary);
		bool CreateBufferToWrite();
		bool ApplyTagToBuffer(int* output_len);
		bool IsValidTagString(String^ tag_string);

		static const gcroot<String^> kMagicBytes = "Gact";
		static const unsigned int kPEHeaderOffset = 60;

		// The string to be tagged into the binary.
		gcroot<String^> tag_string_;

		// Existing tag string inside the binary.
		gcroot<String^> prev_tag_string_;

		// This is prev_tag_string_.size - 1, to exclude the terminating null.
		int prev_tag_string_length_;

		// Length of the certificate inside the binary.
		int prev_cert_length_;

		// The input binary to be tagged.
		gcroot<String^> signed_exe_file_;

		// The output binary name.
		gcroot<String^> tagged_file_;

		// Whether to append the tag string to the existing one.
		bool append_;

		// Internal buffer to hold the appended string.
		gcroot<String^> tag_buffer_;

		// The output buffer that contains the original binary
		// data with the tagged information.
		gcroot<array<unsigned char>^> buffer_data_;
	};
}