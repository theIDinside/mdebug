/** LICENSE TEMPLATE */
// mdb
#include <common/panic.h>
#include <interface/remotegdb/deserialization.h>
#include <register_description.h>

namespace mdb {
constexpr void
RegisterDescription::RegisterBuffer::Swap(RegisterBuffer &other) noexcept
{
  std::swap(mBuffer, other.mBuffer);
  std::swap(mSize, other.mSize);
}

constexpr RegisterDescription::RegisterBuffer::RegisterBuffer(u8 *buffer, u32 size) noexcept
    : mBuffer(buffer), mSize(size)
{
}
constexpr RegisterDescription::RegisterBuffer::RegisterBuffer(RegisterBuffer &&other) noexcept { Swap(other); }

constexpr RegisterDescription::RegisterBuffer &
RegisterDescription::RegisterBuffer::operator=(RegisterBuffer &&other) noexcept
{
  if (this != &other) {
    delete mBuffer;
    mBuffer = nullptr;
    mSize = 0;
    Swap(other);
  }
  return *this;
}

constexpr RegisterDescription::RegisterBuffer::~RegisterBuffer() noexcept
{
  if (mBuffer) {
    delete mBuffer;
  }
}

u64
RegisterDescription::RegisterBuffer::Size() const noexcept
{
  return mSize;
}

RegisterDescription::RegisterDescription(gdb::ArchictectureInfo *archInfo) noexcept
    : mArchInfo(archInfo), mRIPOffset(mArchInfo->mDebugContextRegisters->mRIPOffset),
      mRSPOffset(mArchInfo->mDebugContextRegisters->mRSPOffset),
      mRBPOffset(mArchInfo->mDebugContextRegisters->mRBPOffset),
      mRegisterContents(new u8[mArchInfo->register_bytes()], mArchInfo->register_bytes())
{
}

AddrPtr
RegisterDescription::GetPc() const noexcept
{
  const u8 *ptr = mRegisterContents.Data() + mRIPOffset;
  AddrPtr result;
  std::memcpy(&result, ptr, 8);
  return result;
}

void
RegisterDescription::SetPc(AddrPtr addr) noexcept
{
  std::memcpy(mRegisterContents.Data() + mRIPOffset, &addr, 8);
}

u64
RegisterDescription::GetRegister(u32 regNumber) const noexcept
{
  auto &md = (*mArchInfo->mRegisters->mRegisterMetaData)[regNumber];
  switch (md.bit_size) {
  case 32: {
    u32 res;
    std::memcpy(&res, mRegisterContents.Data(md.mOffset), 4);
    return res;
  } break;
  case 64: {
    u64 res;
    std::memcpy(&res, mRegisterContents.Data(md.mOffset), 8);
    return res;
  } break;
  default:
    break;
  }
  NEVER("Internal debugger API invariant broken; this should only be used for 32-bit and 64-bit registers");
}

void
RegisterDescription::Store(const std::vector<std::pair<u32, std::vector<u8>>> &data) noexcept
{
  const auto &metaData = mArchInfo->mRegisters->mRegisterMetaData.Cast();
  for (const auto &[number, contents] : data) {
    u8 *ptr = mRegisterContents.Data(metaData[number].mOffset);
    std::memcpy(ptr, contents.data(), contents.size());
  }
}

void
RegisterDescription::FillFromHexEncodedString(std::string_view hexString) noexcept
{
  DeserializeHexEncoded(hexString, mRegisterContents);
}
} // namespace mdb