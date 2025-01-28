/** LICENSE TEMPLATE */
#pragma once
#include "interface/remotegdb/target_description.h"
#include "tracee_pointer.h"
#include "utils/macros.h"
#include <typedefs.h>
namespace mdb {

enum class TargetFormat : u8
{
  Native,
  Remote
};

enum class ArchType : u8
{
  X86_64 = 0,
  COUNT
};

class RegisterDescription
{
  class RegisterBuffer
  {
    u8 *mBuffer = nullptr;
    u32 mSize = 0;

    constexpr void Swap(RegisterBuffer &other) noexcept;

  public:
    using Owned = std::unique_ptr<RegisterBuffer>;
    NO_COPY(RegisterBuffer);

    constexpr explicit RegisterBuffer(u8 *buffer, u32 size) noexcept;
    constexpr RegisterBuffer(RegisterBuffer &&other) noexcept;
    constexpr RegisterBuffer &operator=(RegisterBuffer &&other) noexcept;
    constexpr ~RegisterBuffer() noexcept;

    u64 Size() const noexcept;

    template <class Self>
    u8 *
    Data(this Self &&self) noexcept
    {
      return self.mBuffer;
    }

    template <class Self>
    u8 *
    Data(this Self &&self, u32 offset) noexcept
    {
      ASSERT(offset <= self.mSize, "Offset {} beyond boundary of buffer of size {}", offset, self.mSize);
      return self.mBuffer + offset;
    }

    template <class Self>
    std::span<const u8>
    Span(this Self &&self, u32 offset, u32 length) noexcept
    {
      return std::span<const u8>{self.mBuffer + offset, length};
    }
  };
  // Only three real "interesting" registers from a debugger perspective
  // at least up front; the remaining if they are indeed interesting, are defined
  // by DWARF for us, so we need dwarf information to know about them anyhow, so
  // we will have to look up into the target format data for that.
  gdb::ArchictectureInfo *mArchInfo;
  u16 mRIPOffset;
  u16 mRSPOffset;
  u16 mRBPOffset;
  RegisterBuffer mRegisterContents;

public:
  explicit RegisterDescription(gdb::ArchictectureInfo *archInfo) noexcept;
  ~RegisterDescription() noexcept = default;

  AddrPtr GetPc() const noexcept;
  void SetPc(AddrPtr addr) noexcept;
  u64 GetRegister(u32 regNumber) const noexcept;
  void Store(const std::vector<std::pair<u32, std::vector<u8>>> &data) noexcept;
  void FillFromHexEncodedString(std::string_view hexString) noexcept;
};
} // namespace mdb