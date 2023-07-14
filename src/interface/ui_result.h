#pragma once
#include <concepts>
#include <cstdint>
#include <string>

// clang-format off
template <typename UIType>
concept UI = requires(UIType ui) {
  ui.display_result(std::string{"output to display"});
  ui.display_result(std::string_view{"output to display"});
  { ui.new_result_id() } -> std::convertible_to<std::uint64_t>;
};
// clang-format on
namespace ui {
struct UIResult
{
  virtual ~UIResult() = default;
  virtual std::string serialize(int monotonic_id) const noexcept = 0;

  template <typename Output>
  void
  display_result(Output *output) noexcept
  {
    output->display_result(serialize(output->new_result_id()));
  }
  bool success;
};

// Makes it *somewhat* easier to re-factoer later, if we want to use shared_ptr or unique_ptr here
using UIResultPtr = UIResult *;
} // namespace ui
