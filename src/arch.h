#pragma once
#include "common.h"
#include "ptrace.h"
#include <array>
#include <typedefs.h>
#include <utility>

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

template <ArchType T>
consteval auto
SizeOf() noexcept
{
  switch (T) {
  case ArchType::X86_64:
    return 816;
  case ArchType::COUNT:
    std::unreachable();
  }
}

template <ArchType N> struct ArchRegNum
{
};

struct ArchRegInfo
{
  u8 width;
  u8 num;
  u16 offset;
};

template <size_t ArchSize> consteval std::array<ArchRegInfo, 24> Construct();

template <>
consteval std::array<ArchRegInfo, 24>
Construct<816>()
{
  std::array<ArchRegInfo, 24> regs{};
  auto offset = 0u;
  for (auto i = 0u; i < 24; ++i) {
    regs[i] = ArchRegInfo{8, static_cast<u8>(i), static_cast<u16>(offset)};
    offset += regs[i].width;
  }

  return regs;
}

template <> struct ArchRegNum<ArchType::X86_64>
{

  static constexpr auto DwarfRegisterTable = Construct<SizeOf<ArchType::X86_64>()>();

  static constexpr auto RAX = DwarfRegisterTable[0];
  static constexpr auto RBX = DwarfRegisterTable[1];
  static constexpr auto RCX = DwarfRegisterTable[2];
  static constexpr auto RDX = DwarfRegisterTable[3];
  static constexpr auto RSI = DwarfRegisterTable[4];
  static constexpr auto RDI = DwarfRegisterTable[5];
  static constexpr auto RBP = DwarfRegisterTable[6];
  static constexpr auto RSP = DwarfRegisterTable[7];
  static constexpr auto R8 = DwarfRegisterTable[8];
  static constexpr auto R9 = DwarfRegisterTable[9];
  static constexpr auto R10 = DwarfRegisterTable[10];
  static constexpr auto R11 = DwarfRegisterTable[11];
  static constexpr auto R12 = DwarfRegisterTable[12];
  static constexpr auto R13 = DwarfRegisterTable[13];
  static constexpr auto R14 = DwarfRegisterTable[14];
  static constexpr auto R15 = DwarfRegisterTable[15];
  static constexpr auto RIP = DwarfRegisterTable[16];
  static constexpr auto EFLAGS = DwarfRegisterTable[17];
  static constexpr auto CS = DwarfRegisterTable[18];
  static constexpr auto SS = DwarfRegisterTable[19];
  static constexpr auto DS = DwarfRegisterTable[20];
  static constexpr auto ES = DwarfRegisterTable[21];
  static constexpr auto FS = DwarfRegisterTable[22];
  static constexpr auto GS = DwarfRegisterTable[23];

  static constexpr auto ORIG_RAX = 536;
};

template <ArchType Type> struct RegisterBlock
{
  std::array<u8, SizeOf<Type>()> file;

  u32
  pc_number() const noexcept
  {
    return ArchRegNum<Type>::RIP.num;
  }

  void
  set_file(const std::vector<u8> &data) noexcept
  {
    ASSERT(data.size() == SizeOf<Type>(), "Contents of `data` {} is not of ArchSize: {}", data.size(),
           SizeOf<Type>());
    std::memcpy(file.data(), data.data(), data.size());
  }

  void
  set_registers(const std::vector<std::pair<u32, std::vector<u8>>> &data) noexcept
  {
    for (const auto &[number, contents] : data) {
      ASSERT(ArchRegNum<Type>::DwarfRegisterTable[number].width == contents.size(),
             "Register and incoming data of different width: {} != {}",
             ArchRegNum<Type>::DwarfRegisterTable[number].width, contents.size());
      const auto &info = ArchRegNum<Type>::DwarfRegisterTable[number];
      const auto offset = info.offset;
      u8 *ptr = file.data() + offset;
      std::memcpy(ptr, contents.data(), contents.size());
    }
  }

  constexpr u64
  get_64bit_reg(u32 reg_number)
  {
    const u64 *ptr = (const u64 *)(file.data() + ArchRegNum<Type>::DwarfRegisterTable[reg_number].offset);
    return *ptr;
  }

  constexpr u32
  get_32bit_reg(u32 reg_number)
  {
    const u32 *ptr = (file.data() + ArchRegNum<Type>::DwarfRegisterTable[reg_number].offset);
    return *ptr;
  }

  constexpr AddrPtr
  get_pc() const noexcept
  {
    const auto *ptr = (const u64 *)(file.data() + ArchRegNum<Type>::RIP.offset);
    return AddrPtr{*ptr};
  }

  constexpr uintptr_t
  get_rbp() const noexcept
  {
    const auto ptr = (const u64 *)(file.data() + ArchRegNum<Type>::RBP.offset);
    return *ptr;
  }

  constexpr uintptr_t
  get_rsp() const noexcept
  {
    const auto ptr = (const u64 *)(file.data() + ArchRegNum<Type>::RSP.offset);
    return *ptr;
  }

  constexpr u64
  orig_rax() const noexcept
  {
    const u64 *ptr = (const u64 *)(file.data() + ArchRegNum<Type>::ORIG_RAX);
    return *ptr;
  }

  constexpr void
  set_pc(uintptr_t value) noexcept
  {
    u64 *ptr = (u64 *)(file.data() + ArchRegNum<Type>::RIP.offset);
    *ptr = value;
  }
};