// libFuzzer harness: run one of 7-Zip's raw stream decoders (LZMA, LZMA2, PPMd, BZip2, Deflate, Zstd,
// LZ4, Brotli, ...) on attacker-controlled coder properties and compressed bytes.
// Input: byte 0 selects the decoder, byte 1 (low 4 bits) is the property length, then the
// properties, then the compressed stream.
#include "../CPP/Common/Common.h"
#include "../CPP/Common/MyCom.h"
#include "../CPP/Windows/PropVariant.h"
#include "../CPP/7zip/ICoder.h"
#include "../CPP/7zip/Archive/IArchive.h"
#include "../CPP/7zip/Common/StreamObjects.h"

#include <stdint.h>

STDAPI CreateDecoder(UInt32 index, const GUID *iid, void **outObject);
STDAPI GetNumberOfMethods(UInt32 *numCodecs);
STDAPI GetMethodProperty(UInt32 codecIndex, PROPID propID, PROPVARIANT *value);

static const UInt64 kMaxOutput = 64u << 20;

Z7_CLASS_IMP_COM_1(CCountOutStream, ISequentialOutStream)
public:
  UInt64 Total;
};

Z7_COM7F_IMF(CCountOutStream::Write(const void *, UInt32 size, UInt32 *processedSize))
{
  if (Total + size > kMaxOutput)
    return E_FAIL;
  Total += size;
  if (processedSize)
    *processedSize = size;
  return S_OK;
}

static bool GetBool(UInt32 index, PROPID id, bool def)
{
  NWindows::NCOM::CPropVariant p;
  if (GetMethodProperty(index, id, &p) != S_OK || p.vt != VT_BOOL)
    return def;
  return p.boolVal != VARIANT_FALSE;
}

static UInt32 g_Decoders[256];
static unsigned g_NumDecoders;

static void FindDecoders()
{
  UInt32 n = 0;
  if (GetNumberOfMethods(&n) != S_OK)
    return;
  for (UInt32 i = 0; i < n && g_NumDecoders < 256; i++)
  {
    if (!GetBool(i, NMethodPropID::kDecoderIsAssigned, false))
      continue;
    if (GetBool(i, NMethodPropID::kIsFilter, false))
      continue;
    NWindows::NCOM::CPropVariant p;
    if (GetMethodProperty(i, NMethodPropID::kPackStreams, &p) == S_OK && p.vt == VT_UI4 && p.ulVal != 1)
      continue;
    g_Decoders[g_NumDecoders++] = i;
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (g_NumDecoders == 0)
    FindDecoders();
  if (g_NumDecoders == 0 || size < 2)
    return -1;
  const UInt32 codec = g_Decoders[data[0] % g_NumDecoders];
  size_t propLen = data[1] & 15;
  data += 2;
  size -= 2;
  if (propLen > size)
    return -1;
  const Byte *props = data;
  data += propLen;
  size -= propLen;

  CMyComPtr<ICompressCoder> coder;
  if (CreateDecoder(codec, &IID_ICompressCoder, (void **)&coder) != S_OK || !coder)
    return -1;

  CMyComPtr<ICompressSetDecoderProperties2> setProps;
  coder.QueryInterface(IID_ICompressSetDecoderProperties2, &setProps);
  if (setProps)
  {
    if (setProps->SetDecoderProperties2(props, (UInt32)propLen) != S_OK)
      return -1;
  }
  else if (propLen != 0)
    return -1;

  CBufInStream *inSpec = new CBufInStream;
  CMyComPtr<ISequentialInStream> in(inSpec);
  inSpec->Init(data, size);
  CCountOutStream *outSpec = new CCountOutStream;
  CMyComPtr<ISequentialOutStream> out(outSpec);
  outSpec->Total = 0;

  const UInt64 inSize = size;
  if (coder->Code(in, out, &inSize, NULL, NULL) != S_OK)
    return -1;
  return 0;
}
