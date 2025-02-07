/** LICENSE TEMPLATE */
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#define ReqArg(TypeName, ...)                                                                                     \
  enum class TypeName##Args : u8{__VA_ARGS__};                                                                    \
  static constexpr std::array<std::string_view, count_tuple(#__VA_ARGS__)> ArgNames =                             \
    std::to_array({#__VA_ARGS__});

#define RequiredArguments(...)                                                                                    \
  static constexpr const auto ReqArgs = std::to_array(__VA_ARGS__);                                               \
  static constexpr const auto &Arguments() noexcept { return ReqArgs; }

#define NoRequiredArgs()                                                                                          \
  static constexpr const std::array<std::string_view, 0> ReqArgs{};                                               \
  static constexpr const std::array<std::string_view, 0> &Arguments() noexcept { return ReqArgs; }

#define CTOR(Type)                                                                                                \
  Type(bool success, UICommandPtr cmd) noexcept : UIResult(success, cmd) {}

#define IfInvalidArgsReturn(type)                                                                                 \
  if (const auto missing = Validate<type>(seq, args); missing) {                                                  \
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
  return std::tuple_size<decltype(std::make_tuple(std::string_view{args}...))>::value;
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
  Invalid(std::string_view desc) noexcept
  {
    return ArgumentError{.kind = ArgumentErrorKind::InvalidInput, .description = std::string{desc}};
  }

  constexpr static ArgumentError
  RequiredNumberType() noexcept
  {
    return ArgumentError{.kind = ArgumentErrorKind::InvalidInput,
                         .description = "Argument required to be a number"};
  }

  constexpr static ArgumentError
  RequiredStringType() noexcept
  {
    return ArgumentError{.kind = ArgumentErrorKind::InvalidInput,
                         .description = "Argument required to be a string"};
  }

  constexpr static ArgumentError
  RequiredBooleanType() noexcept
  {
    return ArgumentError{.kind = ArgumentErrorKind::InvalidInput,
                         .description = "Argument required to be a boolean"};
  }

  constexpr static ArgumentError
  RequiredArrayType() noexcept
  {
    return ArgumentError{.kind = ArgumentErrorKind::InvalidInput,
                         .description = "Argument required to be an array"};
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
  static constexpr std::string_view Request{Name};                                                                \
  constexpr std::string_view name() const noexcept final { return Request; }

template <typename DerivedCommand, typename Json>
concept HasValidation = requires(const Json &json) {
  { DerivedCommand::ValidateArg(std::string_view{}, json) } -> std::convertible_to<std::optional<InvalidArg>>;
};

struct UICommand
{
  dap::DebugAdapterClient *mDAPClient;

public:
  explicit UICommand(std::uint64_t seq) noexcept : seq(seq) {}
  virtual ~UICommand() noexcept = default;

  constexpr void
  SetDebugAdapterClient(dap::DebugAdapterClient &da) noexcept
  {
    mDAPClient = &da;
  }

  /* Executes the command. This is always performed in the Tracer thread (where all tracee controller actions are
   * performed. )*/
  virtual UIResultPtr Execute() noexcept = 0;

  UIResultPtr LogExecute() noexcept;

  template <typename Derived, typename JsonArgs>
  static constexpr MissingOrInvalidResult
  CheckArguments(const JsonArgs &args)
  {
    constexpr auto expectedCommandArgs = Derived::Arguments();
    MissingOrInvalidArgs faulty_args;
    for (const auto &arg : expectedCommandArgs) {
      if (auto r = CheckArgumentContains(args, arg); r) {
        faulty_args.push_back(r.value());
      } else if constexpr (HasValidation<Derived, decltype(args[arg])>) {
        if (auto processed = Derived::ValidateArg(arg, args[arg]); processed) {
          faulty_args.emplace_back(processed.value());
        }
      }
    }

    if (faulty_args.empty()) {
      return std::nullopt;
    } else {
      return MissingOrInvalidResult{faulty_args};
    }
  }

  template <typename JsonArgs, typename CommandArg>
  static auto
  CheckArgumentContains(const JsonArgs &args,
                        const CommandArg &cmd_arg) -> std::optional<std::pair<ArgumentError, std::string>>
  {
    if (!args.contains(cmd_arg)) {
      return std::make_pair<ArgumentError, std::string>(
        {ArgumentErrorKind::Missing, "Required argument is missing"}, std::string{cmd_arg});
    }
    return std::nullopt;
  }

  std::uint64_t seq;
  constexpr virtual std::string_view name() const noexcept = 0;
};

// Makes it *somewhat* easier to re-factoer later, if we want to use shared_ptr or unique_ptr here
using UICommandPtr = UICommand *;
}; // namespace ui
} // namespace mdb