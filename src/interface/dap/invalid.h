/** LICENSE TEMPLATE */
#pragma once
#include <interface/ui_command.h>
#include <interface/ui_result.h>

namespace mdb::ui::dap {
struct InvalidArgsResponse final : public UIResult
{
  InvalidArgsResponse(Pid processId, std::string_view command, MissingOrInvalidArgs &&missing_args) noexcept;
  ~InvalidArgsResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
  Pid mProcessId;
  std::string_view command;
  MissingOrInvalidArgs missing_or_invalid;
};

struct InvalidArgs final : public UICommand
{
  InvalidArgs(UICommandArg arg, std::string_view command, MissingOrInvalidArgs &&missing_args) noexcept
      : UICommand(arg), command(command), missing_arguments(std::move(missing_args))
  {
  }
  ~InvalidArgs() override = default;

  UIResultPtr
  Execute() noexcept final
  {
    return new InvalidArgsResponse{mPid, command, std::move(missing_arguments)};
  }

  ArgumentErrorKind kind;
  std::string_view command;
  MissingOrInvalidArgs missing_arguments;

  constexpr std ::string_view
  name() const noexcept final
  {
    return command;
  };
};

template <typename Derived, typename JsonArgs>
constexpr auto
Validate(UICommandArg arg, const JsonArgs &args) -> InvalidArgs *
{
  if (auto &&missing = UICommand::CheckArguments<Derived>(args); missing) {
    return new ui::dap::InvalidArgs{arg, Derived::Request, std::move(missing.value())};
  } else {
    return nullptr;
  }
}
} // namespace mdb::ui::dap