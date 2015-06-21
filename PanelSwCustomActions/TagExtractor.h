#pragma once
#include "stdafx.h"

class CTagExtractor
{
public:
	CTagExtractor();
	~CTagExtractor();

	/**
	* @return true if we successfully opened the file.
	*/
	HRESULT OpenFile(LPCWSTR szFilename);

	/**
	* @return true if we currently have a handle to an open file.
	*/
	bool IsFileOpen() const;

	void CloseFile();

	/**
	* Returns the tag in the current file.
	*
	* We're exploiting the empirical observation that Windows checks the
	* signature on a PEF but doesn't care if the signature container includes
	* extra bytes after the signature.
	*
	* Logic:
	*
	*   - Sanity-check that we're a PEF image.
	*   - Find the signature, which should be stored in the PE "Certificates
	*     Directory" (dumpbin.exe /headers "Firefox Setup 1.0.7.exe") in a
	*     WIN_CERTIFICATE structure.
	*   - Crudely parse the ASN.1 signature to determine its end.
	*   - Read the signature starting from the first byte past the ASN.1.
	*
	* @param tag_buffer: a buffer that will be filled with the extracted tag as
	*   a null-terminated string, or NULL if the caller doesn't want the tag.
	*
	* @param tag_buffer_len: a pointer to an int that represents the length in
	*   bytes of the buffer pointed to by tag_buffer. If tag_buffer is NULL and
	*   there is a tag to extract, then we fill this int with the size of the
	*   smallest buffer needed to contain the tag (plus the null terminator).
	*
	* @return true if we found a tag and either successfully copied all of it
	*   into tag_buffer, or tag_buffer was NULL and we successfully returned
	*   the required buffer size in tag_buffer_len.
	*/
	HRESULT ExtractTag(char* tag_buffer, size_t* tag_buffer_len);
	HRESULT ExtractTag(LPCSTR binary_file, size_t binary_file_length, LPSTR tag_buffer, size_t* tag_buffer_len);

private:
	HANDLE _hFile;
	HANDLE _hFileMapping;
	LPVOID _FileBase;
	size_t _FileSize;
	size_t _iCertificateLength;
	const void* _iCertificateBase;

	HRESULT ReadTag(LPCSTR tag_pointer, LPSTR tag_buffer, size_t* tag_buffer_len) const;

	const void* GetCertificateDirectoryPointer(const void* base) const;

	const void* GetASN1SignaturePointer(const void* base) const;

	size_t GetASN1SignatureLength(const void* base) const;

	HRESULT InternalExtractTag(const char* file_buffer, char* tag_buffer, size_t* tag_buffer_len);

	HRESULT InternalReadCertificate(const char* file_buffer);
};

