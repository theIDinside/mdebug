/** LICENSE TEMPLATE */
#pragma once

// mdb
#include <bp_defs.h>
#include <common/typedefs.h>
#include <interface/attach_args.h>
#include <interface/dap/interface.h>
#include <interface/dap/invalid.h>
#include <interface/dap/types.h>
#include <interface/ui_command.h>
#include <interface/ui_result.h>
#include <json/json.h>
#include <lib/arena_allocator.h>
#include <symbolication/disassemble.h>
#include <utils/format_utils.h>

// stdlib
#include <cctype>
#include <span>

namespace mdb {

using namespace std::string_view_literals;
enum class BreakpointType : std::uint8_t;

namespace ui::dap {

struct Breakpoint;

using namespace std::string_view_literals;

struct VerifyResult
{
  Immutable<std::optional<std::pair<ArgumentError, std::string>>> mArgError;

  std::optional<std::pair<ArgumentError, std::string>> &&
  take() && noexcept
  {
    return std::move(mArgError);
  }

  constexpr
  operator bool() noexcept
  {
    return mArgError->has_value();
  }
};

struct VerifyField
{
  static constexpr auto CurrentEnumMax = 5;
  std::string_view mName;
  FieldType mType;
  std::string_view mErrorMessage{ "" };
  std::array<std::string_view, CurrentEnumMax> mEnumValues{};
  u8 mEnumVariants{ 0 };

  constexpr std::span<const std::string_view>
  GetEnumValues() const noexcept
  {
    if (mEnumVariants == 0) {
      return {};
    }

    return std::span(mEnumValues).subspan(0, mEnumVariants);
  }

  constexpr VerifyField(std::string_view fieldName, FieldType fieldType) noexcept
      : mName(fieldName), mType(fieldType)
  {
  }

  consteval VerifyField(
    std::string_view fieldName, FieldType fieldType, std::array<std::string_view, CurrentEnumMax> enumerations)
      : mName(fieldName), mType(fieldType), mEnumValues(enumerations),
        mEnumVariants(enumerations.size() - std::count(enumerations.begin(), enumerations.end(), ""))
  {
    if (fieldType != FieldType::Enumeration) {
      throw std::exception();
    }
  }

  constexpr bool
  HasEnumVariant(std::string_view value) const noexcept
  {
    for (const auto v : GetEnumValues()) {
      if (value == v) {
        return true;
      }
    }
    return false;
  }
};

template <size_t Size> struct VerifyMap
{
  std::array<VerifyField, Size> mFields;

  template <typename JsonValueType>
  constexpr VerifyResult
  isOK(const JsonValueType &j, std::string_view fieldName) const noexcept
  {
    if (const auto it =
          std::find_if(mFields.cbegin(), mFields.cend(), [&](const auto &f) { return fieldName == f.mName; });
      it != std::cend(mFields)) {
      switch (it->mType) {
      case FieldType::Address:
        if (!j.IsString()) {
          return VerifyResult{ std::make_pair(ArgumentError::RequiredStringType(), fieldName) };
        } else {
          std::string_view s = j.UncheckedGetStringView();
          if (s.starts_with("0x")) {
            s.remove_prefix(2);
          }
          for (auto ch : s) {
            if (!std::isxdigit(ch)) {
              return VerifyResult{ std::make_pair(ArgumentError::RequiredAddressType(), fieldName) };
            }
          }
          return VerifyResult{ std::nullopt };
        }
      case FieldType::String:
        if (!j.IsString()) {
          return VerifyResult{ std::make_pair(ArgumentError::RequiredStringType(), fieldName) };
        }
        break;
      case FieldType::Float:
        [[fallthrough]];
      case FieldType::Int:
        if (!j.IsNumber()) {
          return VerifyResult{ std::make_pair(ArgumentError::RequiredNumberType(), fieldName) };
        }
        break;
      case FieldType::Boolean:
        if (!j.IsBoolean()) {
          return VerifyResult{ std::make_pair(ArgumentError::RequiredBooleanType(), fieldName) };
        }
        break;
      case FieldType::Enumeration: {
        if (!j.IsString()) {
          return VerifyResult{ std::make_pair(
            ArgumentError{ .kind = ArgumentErrorKind::InvalidInput,
              .description = "Config enumeration values must be of string type" },
            fieldName) };
        }
        std::string_view value = j.UncheckedGetStringView();
        if (!it->HasEnumVariant(value)) {
          return VerifyResult{ std::make_pair(
            ArgumentError{ .kind = ArgumentErrorKind::InvalidInput,
              .description = std::format(
                "Invalid variant: '{}'. Valid: {}", value, JoinFormatIterator{ it->GetEnumValues(), "|" }) },
            fieldName) };
        }
        break;
      }
      case FieldType::Array:
        if (!j.IsArray()) {
          return VerifyResult{ std::make_pair(ArgumentError::RequiredArrayType(), fieldName) };
        }
        break;
      }
      return VerifyResult{ std::nullopt };
    } else {
      return VerifyResult{ std::nullopt };
    }
  }
};

#define DefineArgTypes(...)                                                                                       \
  static constexpr auto ArgsFieldsArray = std::to_array<VerifyField>({ __VA_ARGS__ });                            \
  static constexpr VerifyMap<ArgsFieldsArray.size()> ArgTypes{ ArgsFieldsArray };                                 \
  template <typename Json>                                                                                        \
  constexpr static auto ValidateArg(std::string_view argName, const Json &argContents) noexcept                   \
    -> std::optional<InvalidArg>                                                                                  \
  {                                                                                                               \
    if (auto err = ArgTypes.isOK(argContents, argName); err) {                                                    \
      return std::move(err).take();                                                                               \
    }                                                                                                             \
    return std::nullopt;                                                                                          \
  }

class Message
{
  std::pmr::string mFormat;
  std::pmr::unordered_map<std::pmr::string, std::pmr::string> mVariables;
  bool mShowUser{ true };
  std::optional<int> mId{};

public:
  Message(std::string_view message, std::pmr::memory_resource *rsrc) noexcept;
  Message(std::pmr::string message, std::pmr::memory_resource *rsrc) noexcept;

  const auto &
  Variables() const
  {
    return mVariables;
  }

  const auto &
  Format() const noexcept
  {
    return mFormat;
  }

  bool
  ShowToUser() const noexcept
  {
    return mShowUser;
  }
  std::optional<int>
  MessageId() const noexcept
  {
    return mId;
  }
};

// Defined in commands.cpp
struct ErrorResponse;
struct StackTraceResponse;
struct StackTrace;
struct Scopes;

template <typename T>
concept HasName = requires(T t) {
  { T::Request } -> std::convertible_to<std::string_view>;
};

RefPtr<ui::UICommand> ParseDebugAdapterCommand(DebugAdapterClient &client, std::string_view packet) noexcept;

}; // namespace ui::dap
} // namespace mdb
