/** LICENSE TEMPLATE */
#pragma once

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace std::pmr {
class memory_resource;
}

namespace mdbjson {

using u8 = std::uint8_t;
using i64 = std::int64_t;

struct JsonValue;
struct Token;

struct TransparentStringHash
{
  using is_transparent = void;
  std::size_t
  operator()(std::string_view s) const noexcept
  {
    return std::hash<std::string_view>{}(s);
  }
  std::size_t
  operator()(const std::pmr::string &s) const noexcept
  {
    return operator()(std::string_view{ s });
  }
};
struct TransparentStringEq
{
  using is_transparent = void;
  bool
  operator()(std::string_view a, std::string_view b) const noexcept
  {
    return a == b;
  }
  bool
  operator()(const std::pmr::string &a, std::string_view b) const noexcept
  {
    return std::string_view{ a } == b;
  }
  bool
  operator()(std::string_view a, const std::pmr::string &b) const noexcept
  {
    return a == std::string_view{ b };
  }
  bool
  operator()(const std::pmr::string &a, const std::pmr::string &b) const noexcept
  {
    return a == b;
  }
};

using NullType = std::nullptr_t;
using BooleanType = bool;
using NumberType = double;
using StringType = std::pmr::string;
using ArrayType = std::pmr::vector<JsonValue>;
using ObjectType =
  std::pmr::unordered_map<std::pmr::string, JsonValue, TransparentStringHash, TransparentStringEq>;

enum class Type : u8
{
  Null,
  Boolean,
  Number,
  String,
  Array,
  Object
};

struct JsonValue
{
  Type mType{ Type::Null };
  union
  {
    NullType null;
    BooleanType boolean;
    NumberType number;
    StringType *string;
    ArrayType *array;
    ObjectType *object;
  } mData{};

  bool IsBoolean() const noexcept;
  bool IsString() const noexcept;
  bool IsNumber() const noexcept;
  bool IsArray() const noexcept;
  bool IsObject() const noexcept;
  bool IsNull() const noexcept;

  // Unchecked getters do not check what type we have. Considered "unsafe" (unless user explicitly checks before
  // hand).
  const BooleanType *UncheckedGetBoolean() const noexcept;
  const StringType *UncheckedGetString() const noexcept;
  const double *UncheckedGetNumber() const noexcept;
  const ArrayType *UncheckedGetArray() const noexcept;
  const JsonValue *UncheckedGetProperty(std::string_view property) const noexcept;

  const BooleanType *GetBoolean() const noexcept;
  const StringType *GetString() const noexcept;
  const double *GetNumber() const noexcept;
  const ArrayType *GetArray() const noexcept;
  const JsonValue *GetProperty(std::string_view property) const noexcept;
};

#define FOR_EACH_PARSE_ERROR(ERR)                                                                                 \
  ERR(UnexpectedEndOfInput)                                                                                       \
  ERR(InvalidToken)                                                                                               \
  ERR(InvalidNumber)                                                                                              \
  ERR(InvalidStringEscape)                                                                                        \
  ERR(UnexpectedCharacter)                                                                                        \
  ERR(ExpectedColon)                                                                                              \
  ERR(ExpectedCommaOrEnd)                                                                                         \
  ERR(ExpectedValue)

struct ParseError
{
  enum class ErrorKind : u8
  {
#define AS_ENUM(E) E,
    FOR_EACH_PARSE_ERROR(AS_ENUM)
#undef AS_ENUM
  };
  ErrorKind mKind;
  i64 mPosition;
  static std::pmr::string ToString(std::pmr::memory_resource *memoryResource, ParseError error) noexcept;
};

consteval auto
LengthOfError(ParseError::ErrorKind kind)
{
#define CASE_OF(Kind)                                                                                             \
  case ParseError::ErrorKind::Kind:                                                                               \
    return std::string_view{ #Kind }.size();
  switch (kind) {
    FOR_EACH_PARSE_ERROR(CASE_OF)
  }
#undef CASE_OF

  return std::string_view{ "Could not determine error" }.size();
}

std::expected<JsonValue *, ParseError> Parse(std::pmr::memory_resource *jsonAllocator, std::string_view input);

} // namespace mdbjson