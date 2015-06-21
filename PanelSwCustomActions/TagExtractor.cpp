#include "TagExtractor.h"
#include "../CaCommon/WixString.h"
#include <Wintrust.h>

#define TAG_PROPERTY L"POST_SIGNATURE_STRING"

extern "C" __declspec(dllexport) UINT ExtractTag(MSIHANDLE hInstall)
{
	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;
	CWixString szMsiFile;
	CTagExtractor tag_extractor;
	size_t lTagLength = 0;
	CWixString szTag;
	CWixString szAnsiTag;

	hr = WcaInitialize(hInstall, __FUNCTION__);
	BreakExitOnFailure(hr, "Failed to initialize");
	WcaLog(LOGMSG_STANDARD, "Initialized.");

	hr = WcaGetProperty(L"OriginalDatabase", (LPWSTR*)szMsiFile);
	BreakExitOnFailure(hr, "Failed to read property 'OriginalDatabase'");
	BreakExitOnNull(!szMsiFile.IsNullOrEmpty(), hr, E_FAIL, "Failed to read property 'OriginalDatabase'");
	
	hr = tag_extractor.OpenFile((LPCWSTR)szMsiFile);
	BreakExitOnFailure1(hr, "Failed to open file '%ls'", (LPCWSTR)szMsiFile);

	hr = tag_extractor.ExtractTag(NULL, &lTagLength);
	BreakExitOnFailure1(hr, "Failed getting tag length from file '%ls'", (LPCWSTR)szMsiFile);
	if ((hr == S_FALSE) || (lTagLength == 0))
	{
		WcaLog(LOGLEVEL::LOGMSG_STANDARD, "'%ls' Doesn't have post-signature data", (LPCWSTR)szMsiFile);
		ExitFunction();
	}

	hr = szAnsiTag.Allocate(1 + lTagLength / sizeof(WCHAR));
	BreakExitOnFailure(hr, "Failed to allocate memory");

	hr = tag_extractor.ExtractTag((LPSTR)(LPWSTR)szAnsiTag, &lTagLength);
	BreakExitOnFailure1(hr, "Failed reading tag from file '%ls'", (LPCWSTR)szMsiFile);

	hr = szTag.Allocate(1 + lTagLength);
	BreakExitOnFailure(hr, "Failed to allocate memory");

	wsprintfW((LPWSTR)szTag, L"%hs", (LPCSTR)(LPCWSTR)szAnsiTag);

	hr = WcaSetProperty(TAG_PROPERTY, (LPCWSTR)szTag);
	BreakExitOnFailure(hr, "Failed setting property '%ls'", TAG_PROPERTY);

LExit:
	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}


#define MSI_DOS_SIGNATURE	0xCFD0
#define MSI_NT_SIGNATURE	0xB1A1E011
#define AFFILIATE_ID_MAGIC	"Gact"

CTagExtractor::CTagExtractor()
	: _hFile(INVALID_HANDLE_VALUE)
	, _hFileMapping(NULL)
	, _FileBase(NULL) 
	, _FileSize(0) 
	, _iCertificateLength(0)
	, _iCertificateBase(NULL) 
{
}

CTagExtractor::~CTagExtractor() 
{
	CloseFile();
}

HRESULT CTagExtractor::OpenFile(LPCWSTR szFilename) 
{
	HRESULT hr = S_OK;
	SIZE_T querySize = 0;
	MEMORY_BASIC_INFORMATION info;

	CloseFile();
	
	_hFile = ::CreateFile(szFilename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	BreakExitOnNullWithLastError(IsFileOpen(), hr, "Failed openning file for reading");
		
	_hFileMapping = ::CreateFileMapping(_hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	BreakExitOnNullWithLastError(_hFileMapping, hr, "Failed creating file mapping");

	_FileBase = ::MapViewOfFile(_hFileMapping, FILE_MAP_READ, 0, 0, 0);
	BreakExitOnNullWithLastError(_FileBase, hr, "Failed mapping file view");

	::ZeroMemory(&info, sizeof(info));

	querySize = ::VirtualQuery(_FileBase, &info, sizeof(info));
	BreakExitOnNullWithLastError(querySize, hr, "Failed querying file");

	_FileSize = info.RegionSize;

LExit:
	
	if (FAILED(hr))
	{
		CloseFile();
	}

	return hr;
}

bool CTagExtractor::IsFileOpen() const 
{
	return ((_hFile != INVALID_HANDLE_VALUE) && (_hFile != NULL));
}

void CTagExtractor::CloseFile() {
	
	if (_FileBase != NULL) 
	{
		UnmapViewOfFile(_FileBase);
		_FileBase = NULL;
	}

	if (_hFileMapping != NULL) 
	{
		CloseHandle(_hFileMapping);
		_hFileMapping = NULL;
	}

	if (IsFileOpen()) 
	{
		CloseHandle(_hFile);
		_hFile = INVALID_HANDLE_VALUE;
	}
}

HRESULT CTagExtractor::ExtractTag(LPCSTR binary_file, size_t binary_file_length, LPSTR tag_buffer, size_t* tag_buffer_len)
{
	_FileSize = binary_file_length;
	return InternalExtractTag(binary_file, tag_buffer, tag_buffer_len);
}

HRESULT CTagExtractor::ExtractTag(char* tag_buffer, size_t* tag_buffer_len) 
{
	HRESULT hr = S_OK;

	BreakExitOnNull(tag_buffer_len, hr, E_INVALIDARG, "Bad tag_buffer_len pointer");
	BreakExitOnNull(IsFileOpen(), hr, E_INVALIDSTATE, "File is closed");

	hr = InternalExtractTag(static_cast<char*>(_FileBase), tag_buffer, tag_buffer_len);
	BreakExitOnFailure(hr, "Failed extracting tag");

LExit:
	return hr;
}

HRESULT CTagExtractor::InternalReadCertificate(const char* file_buffer) 
{
	HRESULT hr = S_OK;

	BreakExitOnNull(file_buffer, hr, E_INVALIDARG, "Bad file_buffer pointer");

	const void* certificate_directory_pointer = GetCertificateDirectoryPointer(file_buffer);
	BreakExitOnNull(certificate_directory_pointer, hr, E_FAIL, "Failed getting certificate directory");

	const void* asn1_signature_pointer = GetASN1SignaturePointer(certificate_directory_pointer);
	BreakExitOnNull(asn1_signature_pointer, hr, E_FAIL, "Failed getting signature");

	size_t asn1_signature_length = GetASN1SignatureLength(asn1_signature_pointer);
	BreakExitOnNull(asn1_signature_length, hr, E_FAIL, "Failed getting signature length");

	_iCertificateLength = asn1_signature_length;
	_iCertificateBase = certificate_directory_pointer;

LExit:

	return hr;
}

HRESULT CTagExtractor::InternalExtractTag(const char* file_buffer, char* tag_buffer, size_t* tag_buffer_len)
{
	HRESULT hr = S_OK;
	
	BreakExitOnNull(file_buffer, hr, E_INVALIDARG, "Bad file_buffer pointer");
	BreakExitOnNull(tag_buffer_len, hr, E_INVALIDARG, "Bad tag_buffer_len pointer");

	hr = InternalReadCertificate(file_buffer);
	BreakExitOnFailure(hr, "Failed reading certificate");

	const char* read_base = static_cast<const char*>(_iCertificateBase)+ _iCertificateLength;
	
	// Is the file tagged?
	if (read_base >= file_buffer + _FileSize) 
	{
		tag_buffer_len = 0;
		hr = S_FALSE;
		WcaLog(LOGLEVEL::LOGMSG_STANDARD, "The file is not tagged");
		ExitFunction();
	}

	hr = ReadTag(read_base, tag_buffer, tag_buffer_len);
	BreakExitOnFailure(hr, "Failed reading tag");

LExit:

	return hr;
}

HRESULT CTagExtractor::ReadTag(LPCSTR tag_pointer, LPSTR tag_buffer, size_t* tag_buffer_len) const
{
	HRESULT hr = S_OK;
	int mc = 0;
	unsigned short id_len = 0;

	mc = memcmp(tag_pointer, AFFILIATE_ID_MAGIC, strlen(AFFILIATE_ID_MAGIC));
	BreakExitOnNull((0 == mc), hr, E_FAIL, "Bad tag_pointer: %s", tag_pointer);

	tag_pointer += strlen(AFFILIATE_ID_MAGIC);

	const unsigned char* id_len_serialized = reinterpret_cast<const unsigned char*>(tag_pointer);
	id_len = id_len_serialized[0] << 8;
	
	// unsigned char and uint16 get promoted to int.
	id_len = static_cast<short>(id_len + id_len_serialized[1]);

	size_t buffer_size_required = id_len + 1;
	if (tag_buffer == NULL) 
	{
		*tag_buffer_len = buffer_size_required;
		ExitFunction();
	}

	BreakExitOnNull((*tag_buffer_len >= buffer_size_required), hr, E_INSUFFICIENT_BUFFER, "Insufficient buffer size");

	tag_pointer += sizeof(id_len);
	memcpy(tag_buffer, tag_pointer, id_len);
	tag_buffer[id_len] = NULL;

LExit:
	return hr;
}

const void* CTagExtractor::GetCertificateDirectoryPointer( const void* base) const 
{
	const char* image_base = reinterpret_cast<const char*>(base);

	// Is this a PEF?
	const IMAGE_DOS_HEADER* dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(image_base);
	if ((dos_header->e_magic != IMAGE_DOS_SIGNATURE) && (dos_header->e_magic != MSI_DOS_SIGNATURE))
	{
		WcaLog(LOGLEVEL::LOGMSG_STANDARD, "Magic number is %04X. Expected to be %04X (MSI) or IMAGE_DOS_SIGNATURE (EXE/DLL)."
			, dos_header->e_magic
			, MSI_DOS_SIGNATURE
			);
		return NULL;
	}

	// Get PE header.
	const IMAGE_NT_HEADERS* nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS*>
		(image_base + dos_header->e_lfanew);

	// Again, is this a PEF? This code should get an F for not being endian-
	// safe, but it gets an A for working in the real world.
	if ((nt_headers->Signature != IMAGE_NT_SIGNATURE) && (nt_headers->Signature != MSI_NT_SIGNATURE))
	{
		WcaLog(LOGLEVEL::LOGMSG_STANDARD, "nt_headers->Signature=0x%08X rather than %08X (MSI) or IMAGE_NT_SIGNATURE (EXE/DLL)"
			, nt_headers->Signature
			, MSI_NT_SIGNATURE
			);
		return NULL;
	}

	const IMAGE_DATA_DIRECTORY* idd =
		reinterpret_cast<const IMAGE_DATA_DIRECTORY *>
		(&nt_headers->
		OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]);
	if (idd->VirtualAddress != NULL) 
	{
		return image_base + idd->VirtualAddress;
	}

	WcaLog(LOGLEVEL::LOGMSG_STANDARD, "idd->VirtualAddress == NULL");
	return NULL;
}

const void* CTagExtractor::GetASN1SignaturePointer(const void* base) const 
{
	const WIN_CERTIFICATE* cert = reinterpret_cast<const WIN_CERTIFICATE *>(base);

	return cert->bCertificate;
}

size_t CTagExtractor::GetASN1SignatureLength(const void* base) const
{
	
	const unsigned char* sig_base = reinterpret_cast<const unsigned char*>(base);
	WcaLog(LOGLEVEL::LOGMSG_VERBOSE, "sig_base[0]=0x%02X, sig_base[1]=0x%02X, sig_base[2]=0x%02X"
		, sig_base[0]
		, sig_base[1]
		, sig_base[2]
		);

	// No, this isn't a full ASN.1 parser. We're just doing the very bare
	// minimum to extract a length.
	if ((sig_base[0] == 0x30) && (sig_base[1] == 0x82)) 
	{
		size_t len = (sig_base[2] << 8);
		size_t mask = ~size_t(7);
			 
		len += *sig_base++;
		// Windows pads the certificate directory to align at a 8-byte boundary.
		// This piece of code it trying to replicate the logic that is used to
		// calculate the padding to be added to the certificate. It returns
		// the entire length of the certificate directory from the windows
		// certificate directory start to the end of padding.
		// The windows certificate directory has the following structure
		// <WIN_CERTIFICATE><Certificate><Padding>.
		// WIN_CERTIFICATE is the windows certificate directory structure.
		// <Certificate> has the following format:
		// <Magic(2 bytes)><Cert length(2 bytes)><Certificate Data>
		// Note that the "Cert length" does not include the magic bytes or
		// the length.
		//
		// Hence the total length of the certificate is:
		// cert_length + "WIN_CERTIFICATE header size" + magic + length
		// + padding = (cert length + 8 + 2 + 2 + 7) & (0-8)
		return (len + 8 + 2 + 2 + 7) & mask;
	}
	return 0;
}
