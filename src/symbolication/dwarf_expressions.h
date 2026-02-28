/** LICENSE TEMPLATE */
#pragma once

// mdb
#include <symbolication/dwarf_binary_reader.h>
#include <symbolication/dwarf_defs.h>
#include <tracee_pointer.h>
#include <utils/immutable.h>

// std
#include <vector>

namespace mdb {

class ObjectFile;

namespace tc {
class SupervisorState;
}

class TaskInfo;
} // namespace mdb

namespace mdb::sym {

enum class LocationKind : u8
{
  Memory,      // DW_OP_addr, base register + offset, CFA + offset
  Register,    // DW_OP_reg0-31, DW_OP_regx - value is in a register
  Implicit,    // DW_OP_implicit_value, DW_OP_stack_value - value is the literal data
  ImplicitPtr, // DW_OP_implicit_pointer - pointer to optimized-out variable
  Composite,   // DW_OP_piece, DW_OP_bit_piece - multiple pieces
  Unavailable  // Optimized out, DW_OP_GNU_uninit, or missing data
};

struct LocationPiece
{
  LocationKind kind;
  u32 mSizeBytes;      // Size of this piece in bytes
  u32 mSizeBits{ 0 };  // If non-zero, this is a bit piece
  u32 mBitOffset{ 0 }; // Bit offset within the location (for DW_OP_bit_piece)

  union
  {
    u64 uMemoryAddress;
    u64 uRegisterNumber;
    struct
    {
      const u8 *mData;
      u32 mLength;
    } uImplicit;
    u64 uImplicitPointerDieOffset;
  };

  constexpr static LocationPiece
  Memory(u64 address, u32 bytes) noexcept
  {
    LocationPiece piece;
    piece.kind = LocationKind::Memory;
    piece.mSizeBytes = bytes;
    piece.uMemoryAddress = address;
    return piece;
  }

  constexpr static LocationPiece
  Register(u64 registerNumber, u32 bytes) noexcept
  {
    LocationPiece piece;
    piece.kind = LocationKind::Register;
    piece.mSizeBytes = bytes;
    piece.uRegisterNumber = registerNumber;
    return piece;
  }

  constexpr static LocationPiece
  Unavailable(u32 bytes) noexcept
  {
    LocationPiece piece;
    piece.kind = LocationKind::Unavailable;
    piece.mSizeBytes = bytes;
    piece.uMemoryAddress = 0;
    return piece;
  }
};

struct LocationDescription
{
  LocationKind mKind;
  union
  {
    u64 uAddress;        // For simple memory locations (legacy compatibility)
    u64 uRegisterNumber; // For register locations
    u64 uValue;          // For implicit values that fit in u64
  };
  std::vector<LocationPiece> mPieces; // For composite locations

  [[nodiscard]] constexpr bool
  IsSimple() const noexcept
  {
    return mPieces.empty();
  }

  [[nodiscard]] constexpr bool
  IsComposite() const noexcept
  {
    return !mPieces.empty();
  }

  constexpr static LocationDescription
  Memory(u64 addr) noexcept
  {
    LocationDescription desc;
    desc.mKind = LocationKind::Memory;
    desc.uAddress = addr;
    return desc;
  }

  constexpr static LocationDescription
  Register(u64 registerNumber) noexcept
  {
    LocationDescription desc;
    desc.mKind = LocationKind::Register;
    desc.uRegisterNumber = registerNumber;
    return desc;
  }

  constexpr static LocationDescription
  Composite(std::vector<LocationPiece> &&piecesList) noexcept
  {
    LocationDescription desc;
    desc.mKind = LocationKind::Composite;
    desc.uAddress = 0;
    desc.mPieces = std::move(piecesList);
    return desc;
  }
};

namespace dw {
class FrameBaseExpression
{
  Immutable<std::span<const u8>> bytecode;

public:
  constexpr explicit FrameBaseExpression(std::span<const u8> byteCode) noexcept : bytecode(byteCode) {}

  static constexpr FrameBaseExpression
  Empty() noexcept
  {
    return FrameBaseExpression{ {} };
  }

  static constexpr FrameBaseExpression
  Take(std::optional<std::span<const u8>> byteCode) noexcept
  {
    return FrameBaseExpression{ byteCode.value_or(std::span<const u8>{}) };
  }

  std::span<const u8>
  GetExpression() const noexcept
  {
    return bytecode;
  }

  constexpr bool
  HasExpression() const noexcept
  {
    return !bytecode->empty();
  }
};
} // namespace dw

struct UnwindInfo;

struct StackValue
{
  bool is_signed;
  union
  {
    u64 u;
    i64 i;
  };
};

struct DwarfStack
{
  DwarfStack() = default;
  ~DwarfStack() = default;

  template <std::integral T>
  void
  Push(T t) noexcept
  {
    MDB_ASSERT(mStackSize < mStack.size(), "Attempting to push value to stack when it's full");
    mStack[mStackSize] = static_cast<u64>(t);
    ++mStackSize;
  }
  u64 Pop() noexcept;
  void Dup() noexcept;
  void Rotate() noexcept;
  void Copy(u8 index) noexcept;
  void Swap() noexcept;

  u16 mStackSize;
  std::array<u64, 1028> mStack;
};

// The byte code interpreter needs all state set up, so that any possibly data it reference during execution, is
// already "there".
struct ExprByteCodeInterpreter
{
  explicit ExprByteCodeInterpreter(int frameLevel,
    tc::SupervisorState &tc,
    TaskInfo &t,
    std::span<const u8> byteStream,
    ObjectFile *objectFile) noexcept;
  explicit ExprByteCodeInterpreter(int frameLevel,
    tc::SupervisorState &tc,
    TaskInfo &t,
    std::span<const u8> byteStream,
    std::span<const u8> frameBaseCode,
    ObjectFile *objectFile) noexcept;
  AddrPtr ComputeFrameBase() noexcept;
  // Read contents of register, at frame level `mFrameLevel` - if registers hasn't been unwound, or if that
  // register for some reason could not be determined, returns nullopt.
  std::optional<u64> GetRegister(u64 number);

  LocationDescription Run() noexcept;

  int mFrameLevel;
  DwarfStack mStack;
  DwarfOp mLatestDecoded;
  tc::SupervisorState &mSupervisor;
  TaskInfo &mTask;
  std::span<const u8> mByteStream;
  std::span<const u8> mFrameBaseProgram;
  ObjectFile *mObjectFile;
  DwarfBinaryReader mReader;

  // Piece tracking for composite locations
  std::vector<LocationPiece> mPieces;
  bool mIsComposite{ false };
};

using Op = void (*)(ExprByteCodeInterpreter &);

} // namespace mdb::sym
