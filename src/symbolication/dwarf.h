#pragma once

#include <common.h>
#include <symbolication/dwarf_defs.h>

template <typename T> concept UnsignedWord = std::is_same_v<T, u32> || std::is_same_v<T, u64>;

struct StrSlice
{
  const char *ptr;
  u64 size;
};

#define ATTR_CTOR(DataType, field)                                                                                \
  constexpr AttributeValue(DataType data, AttributeForm form, Attribute name) noexcept                            \
      : form{form}, name{name}, value{data}                                                                       \
  {                                                                                                               \
  }

template <typename T>
concept AttributeValueType =
  std::is_same_v<T, u64> || std::is_same_v<T, i64> || std::is_same_v<T, DataBlock> ||
  std::is_same_v<T, StrSlice> || std::is_same_v<T, std::string_view> || std::is_same_v<T, AddrPtr>;

/** Fully-formed attribtue */
struct AttributeValue
{
  template <AttributeValueType T>
  constexpr AttributeValue(T value, AttributeForm form, Attribute name) noexcept
      : form{form}, name{name}, value{value}
  {
  }

  constexpr AttributeValue(const AttributeValue &other) : form(other.form), name(other.name), value(other.value) {}
  constexpr AttributeValue &
  operator=(const AttributeValue &other)
  {
    if (this != &other) {
      std::memcpy(this, &other, sizeof(AttributeValue));
    }
    return *this;
  }

  constexpr AttributeValue(AttributeValue &&other) noexcept
      : form(other.form), name(other.name), value(other.value)
  {
  }
  constexpr AttributeValue &
  operator=(AttributeValue &&other) noexcept
  {
    if (this == &other) {
      return *this;
    }
    form = other.form;
    name = other.name;
    value = other.value;
    return *this;
  }

  std::uintptr_t
  address() const noexcept
  {
    return value.addr;
  }
  std::string_view
  string() const noexcept
  {
    return value.str;
  }
  DataBlock
  block() const noexcept
  {
    return value.block;
  }
  u64
  unsigned_value() const noexcept
  {
    return value.u;
  }
  i64
  signed_value() const noexcept
  {
    return value.i;
  }

  static std::string_view
  as_string(const AttributeValue &v) noexcept
  {
    return v.string();
  }

  // std::uintptr_t address() const noexcept;
  // std::string_view string() const noexcept;
  // DataBlock block() const noexcept;
  // u64 unsigned_value() const noexcept;
  // i64 signed_value() const noexcept;
  AttributeForm form;
  Attribute name;

private:
#if defined(COMPILERUSED_GCC)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wclass-memaccess"
#endif
  union _value
  { // Size = 16 bytes
    constexpr _value(std::string_view str) noexcept : str{str} {}
    constexpr _value(DataBlock block) noexcept : block(block) {}
    constexpr _value(u64 u) noexcept : u(u) {}
    constexpr _value(i64 i) noexcept : i(i) {}
    constexpr _value(AddrPtr ptr) noexcept : addr(ptr) {}
    constexpr _value(const _value &other)
    {
      if (this == &other) {
        return;
      }
      std::memcpy(this, &other, sizeof(_value));
    }

    constexpr _value &
    operator=(const _value &other)
    {
      if (this != &other) {
        std::memcpy(this, &other, sizeof(_value));
      }
      return *this;
    }

    DataBlock block;
    // StrSlice str;
    std::string_view str;
    u64 u;
    i64 i;
    AddrPtr addr;
  } value;
#if defined(COMPILERUSED_GCC)
#pragma GCC diagnostic pop
#endif
};