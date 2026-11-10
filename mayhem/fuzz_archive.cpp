// libFuzzer harness: open an archive with one of 7-Zip's statically linked format handlers
// (7z, zip, rar, tar, cab, iso, wim, ...), then extract every item in test mode.
// Input: byte 0 selects the format, the remaining bytes are the archive.
#include "../CPP/Common/Common.h"
#include "../CPP/Common/MyCom.h"
#include "../CPP/Windows/PropVariant.h"
#include "../CPP/7zip/IPassword.h"
#include "../CPP/7zip/Archive/IArchive.h"
#include "../CPP/7zip/Common/StreamObjects.h"

#include <stdint.h>
#include <string.h>

STDAPI CreateObject(const GUID *clsid, const GUID *iid, void **outObject);
STDAPI GetNumberOfFormats(UInt32 *numFormats);
STDAPI GetHandlerProperty2(UInt32 formatIndex, PROPID propID, PROPVARIANT *value);

static const UInt64 kMaxOutput = 64u << 20;

Z7_CLASS_IMP_COM_1(CCountOutStream, ISequentialOutStream)
public:
  UInt64 *Total;
};

Z7_CLASS_IMP_COM_2(COpenCb, IArchiveOpenCallback, ICryptoGetTextPassword)
};

Z7_COM7F_IMF(COpenCb::SetTotal(const UInt64 *, const UInt64 *)) { return S_OK; }
Z7_COM7F_IMF(COpenCb::SetCompleted(const UInt64 *, const UInt64 *)) { return S_OK; }
Z7_COM7F_IMF(COpenCb::CryptoGetTextPassword(BSTR *password))
{
  *password = ::SysAllocString(L"password");
  return *password ? S_OK : E_OUTOFMEMORY;
}

Z7_COM7F_IMF(CCountOutStream::Write(const void *, UInt32 size, UInt32 *processedSize))
{
  if (*Total + size > kMaxOutput)
    return E_FAIL;
  *Total += size;
  if (processedSize)
    *processedSize = size;
  return S_OK;
}

Z7_CLASS_IMP_COM_2(CExtractCb, IArchiveExtractCallback, ICryptoGetTextPassword)
  Z7_IFACE_COM7_IMP(IProgress)
public:
  UInt64 Total;
};

Z7_COM7F_IMF(CExtractCb::SetTotal(UInt64)) { return S_OK; }
Z7_COM7F_IMF(CExtractCb::SetCompleted(const UInt64 *)) { return S_OK; }
Z7_COM7F_IMF(CExtractCb::GetStream(UInt32, ISequentialOutStream **outStream, Int32 askExtractMode))
{
  *outStream = NULL;
  if (askExtractMode != NArchive::NExtract::NAskMode::kExtract)
    return S_OK;
  CCountOutStream *s = new CCountOutStream;
  s->Total = &Total;
  CMyComPtr<ISequentialOutStream> p(s);
  *outStream = p.Detach();
  return S_OK;
}
Z7_COM7F_IMF(CExtractCb::PrepareOperation(Int32)) { return S_OK; }
Z7_COM7F_IMF(CExtractCb::SetOperationResult(Int32)) { return S_OK; }
Z7_COM7F_IMF(CExtractCb::CryptoGetTextPassword(BSTR *password))
{
  *password = ::SysAllocString(L"password");
  return *password ? S_OK : E_OUTOFMEMORY;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < 2)
    return -1;
  UInt32 numFormats = 0;
  if (GetNumberOfFormats(&numFormats) != S_OK || numFormats == 0)
    return -1;
  const UInt32 fmt = data[0] % numFormats;
  data++;
  size--;

  NWindows::NCOM::CPropVariant prop;
  if (GetHandlerProperty2(fmt, NArchive::NHandlerPropID::kClassID, &prop) != S_OK ||
      prop.vt != VT_BSTR || ::SysStringByteLen(prop.bstrVal) != sizeof(GUID))
    return -1;
  GUID clsid;
  memcpy(&clsid, prop.bstrVal, sizeof(GUID));

  CMyComPtr<IInArchive> arc;
  if (CreateObject(&clsid, &IID_IInArchive, (void **)&arc) != S_OK || !arc)
    return -1;

  CBufInStream *inStreamSpec = new CBufInStream;
  CMyComPtr<IInStream> inStream(inStreamSpec);
  inStreamSpec->Init(data, size);

  const UInt64 maxCheck = 1 << 20;
  CMyComPtr<IArchiveOpenCallback> openCb(new COpenCb);
  if (arc->Open(inStream, &maxCheck, openCb) != S_OK)
    return -1;

  UInt32 numItems = 0;
  arc->GetNumberOfItems(&numItems);
  for (UInt32 i = 0; i < numItems && i < 64; i++)
  {
    NWindows::NCOM::CPropVariant p;
    arc->GetProperty(i, kpidPath, &p);
  }

  CExtractCb *cbSpec = new CExtractCb;
  CMyComPtr<IArchiveExtractCallback> cb(cbSpec);
  cbSpec->Total = 0;
  arc->Extract(NULL, (UInt32)(Int32)-1, 1, cb);
  arc->Close();
  return 0;
}
