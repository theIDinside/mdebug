/** LICENSE TEMPLATE */
#pragma once
// mdb

#include <common/typedefs.h>
#include <lib/arena_allocator.h>

// mdblib
#include <json/json.h>

// stdlib
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#define ReqArg(TypeName, ...)                                                                                     \
  enum class TypeName##Args : u8{ __VA_ARGS__ };                                                                  \
  static constexpr std::array<std::string_view, count_tuple(#__VA_ARGS__)> ArgNames =                             \
    std::to_array({ #__VA_ARGS__ });

#define RequiredArguments(...)                                                                                    \
  static constexpr const auto ReqArgs = std::to_array(__VA_ARGS__);                                               \
  static constexpr const auto &Arguments() noexcept { return ReqArgs; }

#define NoRequiredArgs()                                                                                          \
  static constexpr const std::array<std::string_view, 0> ReqArgs{};                                               \
  static constexpr const std::array<std::string_view, 0> &Arguments() noexcept { return ReqArgs; }

#define CTOR(Type)                                                                                                \
  Type(bool success, UICommandPtr cmd) noexcept : UIResult(success, cmd) {}

#define IfInvalidArgsReturn(type)                                                                                 \
  if (const auto missing = Validate<type>(arg, args); missing) {                                                  \
    return missing;                                                                                               \
  }

namespace mdb {

class Tracer;
class TraceeController;
namespace ui {

namespace dap {
class DebugAdapterClient;

template <typename... Args>
consteval auto
count_tuple(Args... args)
{
  return std::tuple_size<decltype(std::make_tuple(std::string_view{ args }...))>::value;
}

} // namespace dap

struct UIResult;
using UIResultPtr = const UIResult *;

enum class ArgumentErrorKind
{
  Missing,
  InvalidInput,
};

struct ArgumentError
{
  ArgumentErrorKind kind;
  std::optional<std::string> description;

  constexpr static ArgumentError
  Missing(std::string_view description)
  {
    return ArgumentError{ .kind = ArgumentErrorKind::Missing,
      .description = std::make_optional<std::string>(description) };
  }

  constexpr static ArgumentError
  Invalid(std::string_view desc) noexcept
  {
    return ArgumentError{ .kind = ArgumentErrorKind::InvalidInput, .description = std::string{ desc } };
  }

  constexpr static ArgumentError
  RequiredNumberType() noexcept
  {
    return ArgumentError{ .kind = ArgumentErrorKind::InvalidInput,
      .description = "Argument required to be a number" };
  }

  constexpr static ArgumentError
  RequiredStringType() noexcept
  {
    return ArgumentError{ .kind = ArgumentErrorKind::InvalidInput,
      .description = "Argument required to be a string" };
  }

  constexpr static ArgumentError
  RequiredAddressType() noexcept
  {
    return ArgumentError{ .kind = ArgumentErrorKind::InvalidInput,
      .description =
        "Argument required to be a string in the format of a hexadecimal address (0x can be omitted)." };
  }

  constexpr static ArgumentError
  RequiredBooleanType() noexcept
  {
    return ArgumentError{ .kind = ArgumentErrorKind::InvalidInput,
      .description = "Argument required to be a boolean" };
  }

  constexpr static ArgumentError
  RequiredArrayType() noexcept
  {
    return ArgumentError{ .kind = ArgumentErrorKind::InvalidInput,
      .description = "Argument required to be an array" };
  }
};

using InvalidArg = std::pair<ArgumentError, std::string>;
using MissingOrInvalidArgs = std::vector<InvalidArg>;
using MissingOrInvalidResult = std::optional<MissingOrInvalidArgs>;

/* #if defined(MDB_DEBUG) and MDB_DEBUG == 1
 * #define DEFINE_NAME(Type) \
 *   constexpr std::string_view name() noexcept override final { return #Type; }
 * #else
 * #define DEFINE_NAME(Type)
 * #endif
 */

#define DEFINE_NAME(Name)                                                                                         \
  static constexpr std::string_view Request{ Name };                                                              \
  constexpr std::string_view name() const noexcept final { return Request; }

template <typename DerivedCommand, typename Json>
concept HasValidation = requires(const Json &json) {
  { DerivedCommand::ValidateArg(std::string_view{}, json) } -> std::convertible_to<std::optional<InvalidArg>>;
};

struct UICommandArg
{
  u64 mSeq;
  SessionId mSessionId;
  std::unique_ptr<alloc::ScopedArenaAllocator> allocator;
};

struct UICommand
{
  using RequestResponseAllocator = std::unique_ptr<alloc::ScopedArenaAllocator>;
  dap::DebugAdapterClient *mDAPClient;
  SessionId mSessionId;
  std::unique_ptr<alloc::ScopedArenaAllocator> mCommandAllocator;
  friend class UIResult;

public:
  std::uint64_t mSeq;

  explicit UICommand(UICommandArg arg) noexcept
      : mSessionId(arg.mSessionId), mCommandAllocator(std::move(arg.allocator)), mSeq(arg.mSeq)
  {
  }

  virtual ~UICommand() noexcept = default;

  constexpr void
  SetDebugAdapterClient(dap::DebugAdapterClient &debugAdapter) noexcept
  {
    mDAPClient = &debugAdapter;
  }

  TraceeController *GetSupervisor() noexcept;

  /** Returns either the result or nullptr. If nullptr is returned, it's because it's been queued/scheduled in the
   * delayed events queue, because some particular-to-the-DAP request ordering is required.*/
  virtual UIResultPtr Execute() noexcept = 0;

  template <typename Derived, typename JsonArgs>
  static constexpr MissingOrInvalidResult
  CheckArguments(const JsonArgs &args)
  {
    constexpr auto expectedCommandArgs = Derived::Arguments();
    MissingOrInvalidArgs faultyArgs;
    for (const auto &arg : expectedCommandArgs) {
      if (auto r = CheckArgumentContains(args, arg); r) {
        faultyArgs.push_back(r.value());
      } else if constexpr (HasValidation<Derived, const mdbjson::JsonValue &>) {
        if (auto processed = Derived::ValidateArg(arg, *args.At(arg)); processed) {
          faultyArgs.emplace_back(processed.value());
        }
      }
    }

    if (faultyArgs.empty()) {
      return std::nullopt;
    } else {
      return MissingOrInvalidResult{ faultyArgs };
    }
  }

  template <typename JsonArgs, typename CommandArg>
  static auto
  CheckArgumentContains(const JsonArgs &args, const CommandArg &commandArg)
    -> std::optional<std::pair<ArgumentError, std::string>>
  {
    if (!args.Contains(commandArg)) {
      return std::make_pair<ArgumentError, std::string>(
        { ArgumentErrorKind::Missing, "Required argument is missing" }, std::string{ commandArg });
    }
    return std::nullopt;
  }

  constexpr virtual std::string_view name() const noexcept = 0;
};

// Makes it *somewhat* easier to re-factoer later, if we want to use shared_ptr or unique_ptr here
using UICommandPtr = UICommand *;
}; // namespace ui
} // namespace mdb