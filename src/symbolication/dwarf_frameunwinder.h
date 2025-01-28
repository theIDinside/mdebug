/** LICENSE TEMPLATE */
#pragma once
#include "../common.h"
#include "block.h"
#include "dwarf_defs.h"
#include "symbolication/callstack.h"

namespace mdb {
struct ElfSection;
class ObjectFile;
class SymbolFile;
class TraceeController;
struct TaskInfo;
class DwarfBinaryReader;
class Elf;
} // namespace mdb

namespace mdb::sym {

struct UnwinderSymbolFilePair;
struct UnwindInfoSymbolFilePair;
struct UnwindInfo;

static constexpr auto TOP2_BITS = 0xC0;
static constexpr auto BOTTOM6_BITS = 0x3f;

enum class RegisterRule : u8
{
  Undefined = 0,   // Not able to to recover register value
  SameValue,       // No change
  Offset,          // Previous value of register is stored at address CFA + N
  ValueOffset,     // Previous value of register is the value of CFA + N
  Register,        // Previous value of register, is stored in another register
  Expression,      // DWARF Expression that points to an address where the register value is located
  ValueExpression, // DWARF Expression that produces the value of the register
  IsCFARegister,   // For all I know the "CFA" is always the "previous frame's stack pointer (rsp)". As such,
  // when a CFA is computed for a frame, it automatically provides the stackpointer value for the previous frame
  // (the "caller" frame, or the one above), because in that frame, the stack pointer is this' frame CFA
};

struct Reg
{
  Reg() noexcept;
  union
  {
    u64 uValue;
    i64 uOffset;
    std::span<const u8> uExpression;
  };
  void SetExpression(std::span<const u8> expr) noexcept;
  void SetValueExpression(std::span<const u8> expr) noexcept;
  void SetOffset(i64 offset) noexcept;
  void SetValueOffset(i64 val_offset) noexcept;
  void SetRegister(u64 reg) noexcept;
  RegisterRule mRule;
};

struct CFA
{
  bool mIsExpression;
  union
  {
    struct
    {
      u64 uNumber;
      i64 uOffset;
    } reg;
    std::span<const u8> uExpression;
  };

  void SetRegister(u64 number, i64 offset) noexcept;
  void SetRegister(u64 number) noexcept;
  void SetOffset(i64 offset) noexcept;
  void SetExpression(std::span<const u8> expr) noexcept;
};

template <size_t RegCount> struct FrameRegisters
{
  static constexpr auto RSP = 7;
  // initialize `FrameRegisters` with TaskInfo's register contents
  explicit FrameRegisters(TaskInfo *t) noexcept;

  std::array<u64, RegCount> regs;
};

using Registers = std::array<Reg, 17>;
using RegisterValues = std::array<u64, 17>;

class CFAStateMachine
{
  friend int decode(DwarfBinaryReader &reader, CFAStateMachine &state, const UnwindInfo *cfi);

public:
  CFAStateMachine(TraceeController &tc, TaskInfo &task, UnwindInfoSymbolFilePair cfi, AddrPtr pc) noexcept;

  CFAStateMachine(TraceeController &tc, TaskInfo &task, const RegisterValues &frame_below,
                  UnwindInfoSymbolFilePair cfi, AddrPtr pc) noexcept;
  /* Initialization routine for the statemachine - it saves the current task register into the state machine
   * registers. */
  static CFAStateMachine Init(TraceeController &tc, TaskInfo &task, UnwindInfoSymbolFilePair cfi,
                              AddrPtr pc) noexcept;
  u64 ComputeExpression(std::span<const u8> bytes, int frameLevel = -1) noexcept;
  u64 ResolveRegisterContents(u64 registerNumber, const FrameUnwindState &belowFrame,
                              int frameLevel = -1) noexcept;
  void SetCanonicalFrameAddress(u64 canonicalFrameAddress) noexcept;
  void RememberState() noexcept;
  void RestoreState() noexcept;

  const CFA &GetCanonicalFrameAddressData() const noexcept;
  const Registers &GetRegisters() const noexcept;
  const Reg &GetProgramCounterRegister() const noexcept;
  void Reset(UnwindInfoSymbolFilePair cfi, const RegisterValues &frameBelow, AddrPtr pc) noexcept;
  void Reset(UnwindInfoSymbolFilePair cfi, const FrameUnwindState &belowFrameRegisters, AddrPtr pc) noexcept;
  void SetNoKnownResumeAddress() noexcept;
  constexpr bool
  KnowsResumeAddress()
  {
    return !mResumeAddressUndefined;
  }

private:
  TraceeController &mTraceeController;
  TaskInfo &mTask;
  AddrPtr mFrameDescriptionEntryPc;
  AddrPtr mEndPc;
  CFA mCanonicalFrameAddressData;
  Registers mRuleTable;
  u64 mCanonicalFrameAddressValue;
  bool mResumeAddressUndefined{false};
  std::vector<Registers> mRememberedState;
  std::vector<CFA> mRememberedCFA;
};

struct Enc
{
  DwarfExceptionHeaderApplication mLocationFormat;
  DwarfExceptionHeaderEncoding mValueFormat;
};

struct Augmentation
{
  bool HasAugmentDataField : 1;
  bool HasEHDataField : 1;
  bool HasLanguageSpecificDataArea : 1;
  bool HasPersonalityRoutinePointer : 1;
  bool HasFDEPointerEncoding : 1;
};

struct CommonInformationEntry
{
  u64 mLength;
  DwFormat mDwarfFormat;
  Enc mFrameDescriptionEntryEncoding;
  u8 mAddrSize;
  u8 mSegmentSize;
  u8 mVersion;
  u64 mId;
  std::optional<std::string_view> mAugmentationString;
  // The address of the function (?) that can run this exception frame code. Maybe?
  AddrPtr mPersonalityAddress;
  Enc mLanguageSpecificDataAreaEncoding;
  DwarfExceptionHeaderApplication mExceptionHeaderApplication;
  u64 mCodeAlignFactor;
  i64 mDataAlignFactor;
  u64 mReturnAddressRegister;
  std::span<const u8> mInstructionByteStream;
  // The offset into .debug_frame or .eh_frame where this CIE can be found.
  u64 mSectionOffset;

  constexpr Augmentation
  GetAugmentation() const noexcept
  {
    if (!mAugmentationString) {
      return Augmentation{false, false, false, false, false};
    }

    Augmentation aug{false, false, false, false, false};

    auto &view = mAugmentationString.value();
    const auto sz = view.size();

    for (auto i = 0u; i < sz; ++i) {
      const char ch = view[i];
      switch (ch) {
      case 'z':
        aug.HasAugmentDataField = true;
        break;
      case 'e':
        ASSERT(view[i + 1] == 'h', "Expected augmentation to be 'eh' but wasn't.");
        aug.HasEHDataField = true;
        ++i;
        break;
      case 'L':
        aug.HasLanguageSpecificDataArea = true;
        break;
      case 'P':
        aug.HasPersonalityRoutinePointer = true;
        break;
      case 'R':
        aug.HasFDEPointerEncoding = true;
        break;
      case 'S':
        // found in /lib64/ld-linux-x86-64.so.2, but I don't know what it does.
        break;
      [[unlikely]] default:
        ASSERT(false, "Unknown augmentation specifier");
      }
    }
    return aug;
  }
};

using CIE = CommonInformationEntry;

struct FrameDescriptionEntry
{
  u64 mLength;
  u64 mCommonInfoEntryOffset;
  u64 mAddressRange;
  std::span<u8> mInstructionByteStream;
  u16 mPadding;
};
using FDE = FrameDescriptionEntry;

/** Structure describing where to find unwind info */
struct UnwindInfo
{
  AddrPtr mStart;
  AddrPtr mEnd;
  u8 mCodeAlignFactor;
  i8 mDataAlignFactor;
  u8 mAugmentationDataLength;
  AddrPtr mLanguageSpecificDataAreaAddress;
  CIE *mPointerToCommonInfoEntry;
  std::span<const u8> mInstructionByteStreamFde{};
};

class Unwinder
{
public:
  Unwinder(ObjectFile *objfile) noexcept;
  u64 CommonInfoEntryCount() const noexcept;
  u64 FrameDescriptionEntryCount() const noexcept;

  // Sets `low` to `ptr` _iff_ ptr is lower than current low.
  void SetLowAddress(AddrPtr ptr) noexcept;
  // Sets `high` to `ptr` _iff_ ptr is higher than current high.
  void SetHighAddress(AddrPtr ptr) noexcept;
  const UnwindInfo *GetUnwindInformation(AddrPtr pc) const noexcept;

  // Objfile
  ObjectFile *mObjectFile;
  AddressRange mAddressRange;
  // .debug_frame
  std::vector<CIE> mDwarfDebugCies;
  std::vector<UnwindInfo> mDwarfUnwindInfos;

  // .eh_frame
  std::vector<CIE> mElfEhCies;
  std::vector<UnwindInfo> mElfEhUnwindInfos;
};

struct UnwindInfoSymbolFilePair
{
  const UnwindInfo *mInfo;
  const SymbolFile *mSymbolFile;

  AddrPtr start() const noexcept;
  AddrPtr end() const noexcept;

  // The actual DWARF binary code we use when we run our interpreter
  // If no data is found/can be retrieved, this just returns an empty span/span of size 0
  std::span<const u8> GetCommonInformationEntryData() const;
  std::span<const u8> GetFrameDescriptionEntryData() const;
};

struct UnwinderSymbolFilePair
{
  Unwinder *mUnwinder;
  SymbolFile *mSymbolFile;
  std::optional<UnwindInfoSymbolFilePair> GetUnwinderInfo(AddrPtr pc) noexcept;
};

class UnwindIterator
{
public:
  UnwindIterator(TraceeController *tc, AddrPtr firstPc) noexcept;
  std::optional<UnwindInfoSymbolFilePair> GetInfo(AddrPtr pc) noexcept;
  bool IsNull() const noexcept;

private:
  TraceeController *mTraceeController;
  UnwinderSymbolFilePair mCurrent;
};
using CommonInfoEntryCount = u64;
using FrameDescriptionEntryCount = u64;

std::pair<CommonInfoEntryCount, FrameDescriptionEntryCount>
CountTotalEntriesInElfSection(DwarfBinaryReader reader) noexcept;
std::pair<CommonInfoEntryCount, FrameDescriptionEntryCount>
CountTotalEntriesInDwarfSection(DwarfBinaryReader reader) noexcept;
CommonInformationEntry ReadCommonInformationEntry(u64 length, u64 cie_offset, DwarfBinaryReader &reader) noexcept;
std::unique_ptr<Unwinder> ParseExceptionHeaderSection(ObjectFile *objfile,
                                                      const ElfSection *ehFrameSection) noexcept;
void ParseDwarfDebugFrame(const Elf *elf, Unwinder *unwinderDb, const ElfSection *debugFrame) noexcept;

FrameDescriptionEntry ReadFrameDescriptionEntry(DwarfBinaryReader &reader);

int decode(DwarfBinaryReader &reader, CFAStateMachine &state, const UnwindInfo *cfi);

} // namespace mdb::sym