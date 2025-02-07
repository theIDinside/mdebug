/** LICENSE TEMPLATE */
#include <interface/ui_command.h>
#include <interface/ui_result.h>

namespace mdb::ui::dap {
struct InvalidArgsResponse final : public UIResult
{
  InvalidArgsResponse(std::string_view command, MissingOrInvalidArgs &&missing_args) noexcept;
  ~InvalidArgsResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
  std::string_view command;
  MissingOrInvalidArgs missing_or_invalid;
};

struct InvalidArgs final : public UICommand
{
  InvalidArgs(std::uint64_t seq, std::string_view command, MissingOrInvalidArgs &&missing_args) noexcept
      : UICommand(seq), command(command), missing_arguments(std::move(missing_args))
  {
  }
  ~InvalidArgs() override = default;

  UIResultPtr
  Execute() noexcept final
  {
    return new InvalidArgsResponse{command, std::move(missing_arguments)};
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
static constexpr auto
Validate(uint64_t seq, const JsonArgs &args) -> InvalidArgs *
{
  if (auto &&missing = UICommand::CheckArguments<Derived>(args); missing) {
    return new ui::dap::InvalidArgs{seq, Derived::Request, std::move(missing.value())};
  } else {
    return nullptr;
  }
}
} // namespace mdb::ui::dap