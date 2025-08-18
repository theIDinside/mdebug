/** LICENSE TEMPLATE */
#pragma once

#include <cstdint>
#include <expected>
#include <optional>
#include <print>
#include <source_location>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <vector>

#define MDBJSON_ASSERT(cond, msg)                                                                                 \
  if (!(cond)) {                                                                                                  \
    const auto sloc = std::source_location::current();                                                            \
    std::println(                                                                                                 \
      "{}:{} in {} ASSERT FAILED: " #cond ": {}", sloc.file_name(), sloc.line() - 1, sloc.function_name(), msg);  \
    std::terminate();                                                                                             \
  }

// Type-dependent false (works even before C++17)
template <class...> struct always_false_t : std::false_type
{
};

template <class... Ts> inline constexpr bool always_false = always_false_t<Ts...>::value;

// Also useful for non-type template params (optional)
template <auto...> struct always_false_value : std::false_type
{
};

template <auto... Vs> inline constexpr bool always_false_v = always_false_value<Vs...>::value;

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

#define IF_IS_TYPE(Type) if constexpr (std::is_same_v<T, Type>)

struct JsonValue
{
private:
  struct UncheckedProxy
  {
    const JsonValue *mJsonValue;

    template <typename T>
    constexpr
    operator T() const noexcept
    {
      if constexpr (std::is_same_v<T, bool>) {
        return *mJsonValue->UncheckedGetBoolean();
      } else if constexpr (std::is_same_v<T, std::string_view>) {
        return mJsonValue->UncheckedGetStringView();
      } else if constexpr (std::is_same_v<T, std::string>) {
        return std::string{ mJsonValue->UncheckedGetStringView() };
      } else if constexpr (std::is_same_v<T, double>) {
        return *mJsonValue->UncheckedGetNumber();
      } else if constexpr (std::is_integral_v<T>) {
        double num = *mJsonValue->UncheckedGetNumber();
        return static_cast<T>(num);
      } else if constexpr (std::is_same_v<T, std::span<const JsonValue>>) {
        return std::span{ *mJsonValue->UncheckedGetArray() };
      } else if constexpr (std::is_same_v<std::remove_cvref_t<T>, JsonValue>) {
        return *mJsonValue;
      } else {
        static_assert(always_false<T>, "Unsupported type");
      }
    }

    constexpr const JsonValue *
    operator->() const noexcept
    {
      return mJsonValue;
    }
  };

public:
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

  // Unchecked getters do not check what type we have. Considered "unsafe"
  // (unless user explicitly checks before hand).
  const BooleanType *UncheckedGetBoolean() const noexcept;
  const StringType *UncheckedGetString() const noexcept;
  std::string_view UncheckedGetStringView() const noexcept;
  const double *UncheckedGetNumber() const noexcept;
  const ArrayType *UncheckedGetArray() const noexcept;
  const JsonValue *UncheckedGetProperty(std::string_view property) const noexcept;

  std::span<const JsonValue> AsSpan() const noexcept;
  std::span<const JsonValue> AsSpan(std::string_view property) const noexcept;
  const BooleanType *GetBoolean() const noexcept;
  const StringType *GetString() const noexcept;
  std::optional<std::string_view> GetStringView() const noexcept;
  const double *GetNumber() const noexcept;
  const ArrayType *GetArray() const noexcept;
  const JsonValue *At(std::string_view property) const noexcept;
  std::optional<const JsonValue> Get(std::string_view property) const noexcept;

  template <typename T>
  T
  Value(std::string_view property, T defaultValue) noexcept
  {
    if (auto prop = At(property); prop) {
      if constexpr (std::is_integral_v<T>) {
        if (prop->IsNumber()) {
          return static_cast<T>(*prop->UncheckedGetNumber());
        }
      } else if constexpr (std::is_floating_point_v<T>) {
        if (prop->IsNumber()) {
          return static_cast<T>(*prop->UncheckedGetNumber());
        }
      } else if constexpr (std::is_same_v<T, std::string_view>) {
        if (prop->IsString()) {
          return prop->UncheckedGetStringView();
        }
      } else if constexpr (std::is_same_v<T, bool>) {
        if (prop->IsBoolean()) {
          return *prop->UncheckedGetBoolean();
        }
      }
    }
    return defaultValue;
  }

  bool Contains(std::string_view property) const noexcept;

  // Getter operators that are unchecked. If they fail, they terminate the
  // program. Responsibility is on caller to check that the access will succeed.
  constexpr UncheckedProxy
  operator[](std::string_view property) const noexcept
  {
    MDBJSON_ASSERT(IsObject(), "JsonValue is not of object type");
    return JsonValue::UncheckedProxy{ UncheckedGetProperty(property) };
  }

  constexpr const JsonValue &
  operator[](std::size_t index) const noexcept
  {
    MDBJSON_ASSERT(IsArray(), "JsonValue is not of array type");
    MDBJSON_ASSERT(index < mData.array->size(), "Accessing element outside array");
    return (*mData.array)[index];
  }

  template <typename T>
  T
  Get(std::string_view property) const noexcept
  {
    MDBJSON_ASSERT(IsObject(), "JsonValue is not of object type");

    IF_IS_TYPE(bool) { return *UncheckedGetBoolean(); }
    else IF_IS_TYPE(std::string_view)
    {
      return UncheckedGetStringView();
    }
    else IF_IS_TYPE(double)
    {
      return *UncheckedGetNumber();
    }
    else IF_IS_TYPE(std::span<const JsonValue>)
    {
      return std::span{ *UncheckedGetArray() };
    }
    else IF_IS_TYPE(const JsonValue &)
    {
      return *UncheckedGetProperty(property);
    }
    else
    {
      static_assert(always_false<T>, "Unsupported type to get");
    }
  }
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

std::expected<JsonValue, ParseError> Parse(
  std::pmr::memory_resource *jsonAllocator, std::string_view input) noexcept;

} // namespace mdbjson

template <> struct std::formatter<mdbjson::JsonValue>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename OutIterator>
  OutIterator
  FormatJsonValue(const mdbjson::JsonValue &obj, OutIterator it) const noexcept
  {
    if (obj.IsObject()) {
      return FormatObject(obj, it);
    } else if (obj.IsArray()) {
      return FormatArray(obj, it);
    } else {
      return FormatPrimitive(obj, it);
    }
  }

  template <typename OutIterator>
  OutIterator
  FormatPrimitive(const mdbjson::JsonValue &obj, OutIterator it) const noexcept
  {
    if (obj.IsString()) {
      return std::format_to(it, R"("{}")", obj.UncheckedGetStringView());
    } else if (obj.IsBoolean()) {
      return std::format_to(it, R"({})", *obj.UncheckedGetBoolean());
    } else if (obj.IsNumber()) {
      return std::format_to(it, R"({})", *obj.UncheckedGetNumber());
    } else if (obj.IsNull()) {
      return std::format_to(it, "null");
    }
    return std::format_to(it, "null");
  }

  template <typename OutIterator>
  OutIterator
  FormatArray(const mdbjson::JsonValue &obj, OutIterator it) const noexcept
  {
    *it++ = '[';
    bool first = true;
    for (const auto &v : obj.AsSpan()) {
      if (!first) [[likely]] {
        *it++ = ',';
        it = FormatJsonValue(v, it);
      } else {
        it = FormatJsonValue(v, it);
        first = false;
      }
    }
    return it;
  }

  template <typename OutIterator>
  OutIterator
  FormatObject(const mdbjson::JsonValue &obj, OutIterator it) const noexcept
  {
    *it++ = '{';
    bool first = true;
    for (const auto &[k, v] : *obj.mData.object) {
      if (!first) [[likely]] {
        it = std::format_to(it, R"(, "{}":)", k);
      } else {
        it = std::format_to(it, R"("{}":)", k);
        first = false;
      }
      it = FormatJsonValue(v, it);
    }
    *it++ = '}';
    return it;
  }

  template <typename FormatContext>
  auto
  format(const mdbjson::JsonValue &obj, FormatContext &ctx) const
  {
    return FormatJsonValue(obj, ctx.out());
  }
};