// Copyright 2006-2009 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ========================================================================
//
// Applies a tag to a signed file.

#include "apply_tag.h"
#include <vector>
#include "base/scoped_ptr.h"
#include "omaha/base/utils.h"
#include "omaha/base/extractor.h"

#using <System.Text.RegularExpressions.dll>
#using <system.dll>
using namespace System::IO;
using namespace System::Text::RegularExpressions;
using namespace System;

namespace PostSignatureTag
{
	ApplyTag::ApplyTag()
		: prev_tag_string_length_(0)
		, prev_cert_length_(0)
		, append_(0) 
	{
	}

	bool ApplyTag::IsValidTagString(String^ tag_string) 
	{
		if (System::String::IsNullOrEmpty(tag_string))
		{
			throw gcnew System::ArgumentNullException("tag_string is null/empty");
		}

		Regex^ regex = gcnew Regex("^[-%{}/&=.,_a-zA-Z0-9_]*$");
		return regex->IsMatch(tag_string);
	}

	void ApplyTag::Init(String^ signed_exe_file, String^ tag_string, int tag_string_length, String^ tagged_file, bool append) 
	{
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

		// Check the tag_string for invalid characters.
		if (!IsValidTagString(tag_string))
		{
			throw gcnew ArgumentException("Invalid tag_string");
		}

		signed_exe_file_ = signed_exe_file;
		tagged_file_ = tagged_file;
		append_ = append;
		tag_string_ = tag_string;
	}

	void ApplyTag::EmbedTagString() 
	{
		array<unsigned char>^ input_file_buffer = File::ReadAllBytes(signed_exe_file_);
		if (input_file_buffer->Length == 0)
		{
			throw gcnew ArgumentOutOfRangeException(signed_exe_file_ + " is empty");
		}

		if (!ReadExistingTag(input_file_buffer))
		{
			throw gcnew Exception(signed_exe_file_ + ": Failed checking existing tag");
		}

		if (!append_ && prev_tag_string_length_) 
		{
			// If there is a previous tag and the append flag is not set, then
			// we should error out.
			throw gcnew Exception(signed_exe_file_ + ": Already tagged");
		}

		if (!CreateBufferToWrite()) 
		{
			throw gcnew Exception("Failed creating buffer");
		}

		// The input_file_buffer might contain the previously read tag, in which
		// case the buffer_data_ is larger than the actual output buffer length.
		// The real output buffer length is returned by the ApplyTagToBuffer
		// method.
		buffer_data_->Copy(input_file_buffer);

		int output_length = 0;
		if (!ApplyTagToBuffer(&output_length))
			return E_FAIL;

		std::vector<byte> output_buffer(output_length);
		ASSERT1(static_cast<size_t>(output_length) <= buffer_data_.size());
		copy(buffer_data_.begin(),
			buffer_data_.begin() + output_length,
			output_buffer.begin());
		return WriteEntireFile(tagged_file_, output_buffer);
	}

	unsigned ApplyTag::GetUint32(const void* p) {
		ASSERT1(p);

		const uint32* pu = reinterpret_cast<const uint32*>(p);
		return *pu;
	}

	void ApplyTag::PutUint32(uint32 i, void* p) {
		ASSERT1(p);

		uint32* pu = reinterpret_cast<uint32*>(p);
		*pu = i;
	}

	bool ApplyTag::ReadExistingTag(array<unsigned char>^ binary) {
		ASSERT1(binary);

		int len = 0;
		TagExtractor tag;
		char* bin = reinterpret_cast<char*>(&binary->front());
		ASSERT1(bin);
		if (tag.ExtractTag(bin, binary->size(), NULL, &len)) {
			prev_tag_string_.resize(len);
			if (tag.ExtractTag(bin, binary->size(), &prev_tag_string_.front(), &len)) {
				// The extractor returns the actual length
				// of the string + 1 for the terminating null.
				prev_tag_string_length_ = len - 1;
			}
		}

		// Set the existing certificate length even if previous
		// tag does not exist.
		prev_cert_length_ = tag.cert_length();
		return true;
	}

	bool ApplyTag::CreateBufferToWrite() {
		ASSERT1(!append_ && !prev_tag_string_length_ || append_);
		ASSERT1(!tag_string_.empty());
		ASSERT1(!prev_tag_string_.size() ||
			prev_tag_string_.size() ==
			static_cast<size_t>(prev_tag_string_length_ + 1));

		// Build the tag buffer.
		// The format of the tag buffer is:
		// 000000-000003: 4-byte magic (big-endian)
		// 000004-000005: unsigned 16-bit int string length (big-endian)
		// 000006-??????: ASCII string
		int tag_string_len = tag_string_.size() + prev_tag_string_length_;
		int kMagicBytesLen = ::lstrlenA(kMagicBytes);
		int tag_header_len = kMagicBytesLen + 2;
		int unpadded_tag_buffer_len = tag_string_len + tag_header_len;
		// The tag buffer should be padded to multiples of 8, otherwise it will
		// break the signature of the executable file.
		int padded_tag_buffer_length = (unpadded_tag_buffer_len + 15) & (-8);

		tag_buffer_.clear();
		tag_buffer_.resize(padded_tag_buffer_length, 0);
		memcpy(&tag_buffer_.front(), kMagicBytes, kMagicBytesLen);
		tag_buffer_[kMagicBytesLen] =
			static_cast<char>((tag_string_len & 0xff00) >> 8);
		tag_buffer_[kMagicBytesLen + 1] = static_cast<char>(tag_string_len & 0xff);

		if (prev_tag_string_length_ > 0) {
			copy(prev_tag_string_.begin(),
				prev_tag_string_.end(),
				tag_buffer_.begin() + tag_header_len);
		}

		copy(tag_string_.begin(),
			tag_string_.end(),
			tag_buffer_.begin() + tag_header_len + prev_tag_string_length_);
		ASSERT1(static_cast<int>(tag_buffer_.size()) == padded_tag_buffer_length);

		return true;
	}

	bool ApplyTag::ApplyTagToBuffer(int* output_len) {
		ASSERT1(output_len);

		uint32 original_data_len = buffer_data_.size() - tag_buffer_.size();
		uint32 peheader = GetUint32(&buffer_data_.front() + kPEHeaderOffset);
		uint32 kCertDirAddressOffset = 152;
		uint32 kCertDirInfoSize = 4 + 4;

		ASSERT1(peheader + kCertDirAddressOffset + kCertDirInfoSize <=
			original_data_len);

		// Read certificate directory info.
		uint32 cert_dir_offset = GetUint32(&buffer_data_.front() + peheader +
			kCertDirAddressOffset);
		if (cert_dir_offset == 0)
			return false;
		uint32 cert_dir_len = GetUint32(&buffer_data_.front() + peheader +
			kCertDirAddressOffset + 4);
		ASSERT1(cert_dir_offset + cert_dir_len <= original_data_len);

		// Calculate the new output length.
		int prev_pad_length = cert_dir_len - prev_cert_length_ -
			prev_tag_string_length_;
		ASSERT1(prev_pad_length >= 0);
		int orig_dir_len = cert_dir_len - prev_tag_string_length_ -
			prev_pad_length;
		ASSERT1(orig_dir_len == prev_cert_length_);
		int output_length = original_data_len - prev_tag_string_length_ -
			prev_pad_length + tag_buffer_.size();
		*output_len = output_length;
		ASSERT1(static_cast<size_t>(output_length) <= buffer_data_.size());
		ASSERT1(output_length >= orig_dir_len);

		// Increase the size of certificate directory.
		int new_cert_len = prev_cert_length_ + tag_buffer_.size();
		PutUint32(new_cert_len,
			&buffer_data_.front() + peheader + kCertDirAddressOffset + 4);

		// Read certificate struct info.
		uint32 cert_struct_len = GetUint32(&buffer_data_.front() + cert_dir_offset);
		ASSERT1(!(cert_struct_len > cert_dir_len ||
			cert_struct_len < cert_dir_len - 8));

		// Increase the certificate struct size.
		PutUint32(new_cert_len, &buffer_data_.front() + cert_dir_offset);

		// Copy the tag buffer.
		copy(tag_buffer_.begin(), tag_buffer_.end(),
			buffer_data_.begin() + cert_dir_offset + prev_cert_length_);

		return true;
	}

}
