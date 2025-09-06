/** LICENSE TEMPLATE */
#pragma once
#include "json/json.h"
#include <interface/ui_command.h>
#include <interface/ui_result.h>

namespace mdb::ui::dap {
struct InvalidArgs;
struct InvalidArgsResponse final : public UIResult
{
  InvalidArgsResponse(
    Pid processId, std::string_view command, MissingOrInvalidArgs &&missingArgs, InvalidArgs *cmd) noexcept;
  ~InvalidArgsResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
  Pid mProcessId;
  std::string_view mCommand;
  MissingOrInvalidArgs mMissingOrInvalid;
};

struct InvalidArgs final : public UICommand
{
  InvalidArgs(UICommandArg arg, std::string_view command, MissingOrInvalidArgs &&missingArgs) noexcept
      : UICommand(std::move(arg)), mCommand(command), mMissingArguments(std::move(missingArgs))
  {
  }
  ~InvalidArgs() override = default;

  void
  Execute() noexcept final
  {
    return WriteResponse(InvalidArgsResponse{ mSessionId, mCommand, std::move(mMissingArguments), this });
  }

  ArgumentErrorKind mKind;
  std::string_view mCommand;
  MissingOrInvalidArgs mMissingArguments;

  constexpr std ::string_view
  name() const noexcept final
  {
    return mCommand;
  };
};

template <typename Derived>
constexpr auto
Validate(UICommandArg &arg, const mdbjson::JsonValue &args) -> RefPtr<ui::dap::InvalidArgs>
{
  if (auto &&missing = UICommand::CheckArguments<Derived>(args); missing) {
    return RefPtr<ui::dap::InvalidArgs>::MakeShared(std::move(arg), Derived::Request, std::move(missing.value()));
  } else {
    return nullptr;
  }
}
} // namespace mdb::ui::dap