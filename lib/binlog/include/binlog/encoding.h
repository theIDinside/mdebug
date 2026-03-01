/** Binary Logging Library - Encoding/Decoding */
#pragma once
#include <cstdint>
#include <cstring>
#include <exception>
#include <span>
#include <string_view>
#include <type_traits>

namespace binlog {

// Type aliases
using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using i8 = std::int8_t;
using i16 = std::int16_t;
using i32 = std::int32_t;
using i64 = std::int64_t;

enum class ArgType : u8
{
  SignedInt = 1,   // i64 - all signed integers
  UnsignedInt = 2, // u64 - all unsigned integers
  Float = 3,       // double - all floating point
  Bool = 4,        // u8 - boolean (0 or 1)
  String = 5,      // UTF-8 string with u32 length prefix
  Pointer = 6,     // u64 - pointer address
  Enum = 7,        // u64 - enum as underlying integer
};

class BinaryWriter
{
public:
  template <typename T>
    requires(std::is_trivially_copyable_v<T>)
  static u32
  Write(u8 *buffer, const T &value) noexcept
  {
    std::memcpy(buffer, &value, sizeof(T));
    return sizeof(T);
  }

  static u32
  Write64(u8 *buffer, u64 value) noexcept
  {
    std::memcpy(buffer, &value, sizeof(u64));
    return sizeof(u64);
  }

  static u32
  Write64(u8 *buffer, i64 value) noexcept
  {
    std::memcpy(buffer, &value, sizeof(i64));
    return sizeof(i64);
  }

  static u32
  Write64(u8 *buffer, double value) noexcept
  {
    std::memcpy(buffer, &value, sizeof(double));
    return sizeof(double);
  }

  static u32
  WriteByte(u8 *buffer, u8 value) noexcept
  {
    buffer[0] = value;
    return 1;
  }

  static u32
  WriteTagType(u8 *buffer, ArgType value) noexcept
  {
    u8 byteValue = static_cast<u8>(value);
    if (byteValue == 0) {
      std::terminate();
    }

    *buffer = byteValue;
    return 1;
  }

  static u32
  WriteString(u8 *buffer, std::string_view str) noexcept
  {
    const u32 length = static_cast<u32>(str.size());
    u32 offset = 0;

    std::memcpy(buffer + offset, &length, sizeof(u32));
    offset += sizeof(u32);

    if (length > 0) {
      std::memcpy(buffer + offset, str.data(), length);
      offset += length;
    }

    return offset;
  }

  static u32
  WriteBytes(u8 *buffer, std::span<const u8> bytes) noexcept
  {
    if (!bytes.empty()) {
      std::memcpy(buffer, bytes.data(), bytes.size());
    }
    return static_cast<u32>(bytes.size());
  }
};

class BinaryReader
{
public:
  static u32
  Read64(const u8 *buffer, u64 &value) noexcept
  {
    std::memcpy(&value, buffer, sizeof(u64));
    return sizeof(u64);
  }

  static u32
  ReadByte(const u8 *buffer, u8 &value) noexcept
  {
    value = buffer[0];
    return 1;
  }

  static u32
  ReadString(const u8 *buffer, std::string_view &str) noexcept
  {
    u32 length;
    std::memcpy(&length, buffer, sizeof(u32));
    u32 offset = sizeof(u32);

    if (length > 0) {
      str = std::string_view(reinterpret_cast<const char *>(buffer + offset), length);
      offset += length;
    } else {
      str = std::string_view();
    }

    return offset;
  }
};

/**
 * Forward declaration for recursive type checking.
 */
template <typename T> constexpr ArgType GetArgType() noexcept;

// Primitives are all trivially copyable and as such is trivially serializable
template <typename T>
concept DirectlySerializable =
  std::is_same_v<T, bool> || (std::is_integral_v<T> && !std::is_same_v<T, bool>) || std::is_floating_point_v<T> ||
  std::is_pointer_v<T> || std::is_enum_v<T> || std::is_convertible_v<T, std::string_view>;

template <typename T>
concept HasValueMethod = requires(T t) {
  { t.value() } -> std::convertible_to<typename std::remove_cvref_t<decltype(t.value())>>;
};

template <typename T>
concept Serializable =
  DirectlySerializable<T> || (HasValueMethod<T> && DirectlySerializable<decltype(std::declval<T>().value())>);

// When the arg is not a primitive but has a .value() method that gives a primitive.
template <typename T>
constexpr auto &
UnwrapValue(const T &value) noexcept
{
  if constexpr (HasValueMethod<T> && !DirectlySerializable<T>) {
    return value.value();
  } else {
    return value;
  }
}

template <typename T>
constexpr ArgType
GetArgType() noexcept
{
  if constexpr (std::is_same_v<T, bool>) {
    return ArgType::Bool;
  } else if constexpr (std::is_convertible_v<T, std::string_view>) {
    return ArgType::String;
  } else if constexpr (std::is_integral_v<T> && std::is_signed_v<T>) {
    return ArgType::SignedInt;
  } else if constexpr (std::is_integral_v<T> && std::is_unsigned_v<T>) {
    return ArgType::UnsignedInt;
  } else if constexpr (std::is_floating_point_v<T>) {
    return ArgType::Float;
  } else if constexpr (std::is_enum_v<T>) {
    return ArgType::Enum;
  } else if constexpr (std::is_pointer_v<T>) {
    return ArgType::Pointer;
  } else if constexpr (HasValueMethod<T> && !DirectlySerializable<T>) {
    // If T has .value() and is not directly serializable, unwrap it
    using UnwrappedType = std::remove_cvref_t<decltype(std::declval<T>().value())>;
    return GetArgType<UnwrappedType>();
  } else {
    static_assert(sizeof(T) == 0, "Unsupported argument type for binary logging");
  }
}

} // namespace binlog
