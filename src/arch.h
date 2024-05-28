#pragma once
#include "common.h"
#include "ptrace.h"
#include "utils/util.h"
#include <algorithm>
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
RegisterCount()
{
  switch (T) {
  case ArchType::X86_64:
#ifndef Reg
#define Reg(name, index, width) width,
    return std::to_array<u8>({
#include <defs/x86_64.defs>
                             })
      .size();
#undef Reg
#endif
    break;
  case ArchType::COUNT:
    std::unreachable();
  }
}

template <ArchType T>
consteval auto
Widths() -> std::array<u8, RegisterCount<T>()>
{
  switch (T) {
  case ArchType::X86_64:
#ifndef Reg
#define Reg(name, index, width) width,
    return std::to_array<u8>({
#include <defs/x86_64.defs>
    });
#undef Reg
#endif
    break;
  case ArchType::COUNT:
    std::unreachable();
  }
}

template <ArchType T>
consteval auto
ArchRegisterBlockSize() noexcept
{
  switch (T) {
  case ArchType::X86_64: {
    constexpr auto array = Widths<T>();
    auto reg_file_size = 0;
    for (auto width : array) {
      reg_file_size += width;
    }
    return reg_file_size;
  }
  case ArchType::COUNT:
    std::unreachable();
  }
}

struct ArchRegInfo
{
  u8 width;
  u8 num;
  u16 offset;
};

template <ArchType T>
consteval std::array<ArchRegInfo, Widths<T>().size()>
Construct()
{
  switch (T) {
  case ArchType::X86_64: {
    constexpr auto arr = Widths<T>();
    std::array<ArchRegInfo, arr.size()> regs{};
    auto offset = 0u;
    for (auto i = 0u; i < arr.size(); ++i) {
      regs[i] = ArchRegInfo{arr[i], static_cast<u8>(i), static_cast<u16>(offset)};
      offset += arr[i];
    }

    return regs;
  } break;
  case ArchType::COUNT:
    break;
  }
}

template <ArchType Architecture> struct ArchRegNum
{

  static constexpr auto DwarfRegisterTable = Construct<Architecture>();

#ifndef Reg
#define Reg(name, index, width) static constexpr auto name = DwarfRegisterTable[index];
#include <defs/x86_64.defs>
#undef Reg
#endif
};

template <ArchType Type> struct RegisterBlock
{
  std::array<u8, ArchRegisterBlockSize<Type>()> file;

  u32
  pc_number() const noexcept
  {
    return ArchRegNum<Type>::RIP.num;
  }

  void
  set_file(const std::vector<u8> &data) noexcept
  {
    ASSERT(data.size() == ArchRegisterBlockSize<Type>(), "Contents of `data` {} is not of ArchSize: {}",
           data.size(), ArchRegisterBlockSize<Type>());
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

  void
  from_hexdigit_encoding(std::string_view hex_encoded) noexcept
  {
    utils::deserialize_hex_encoded(hex_encoded, file);
  }
};