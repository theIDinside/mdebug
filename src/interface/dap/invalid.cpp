/** LICENSE TEMPLATE */
#include "invalid.h"
#include <array>
#include <fmt/core.h>
#include <fmt/ranges.h>

namespace mdb::ui::dap {
InvalidArgsResponse::InvalidArgsResponse(std::string_view command, MissingOrInvalidArgs &&missing_args) noexcept
    : command(command), missing_or_invalid(std::move(missing_args))
{
}

std::pmr::string
InvalidArgsResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::vector<std::string_view> missing{arenaAllocator};
  std::pmr::vector<const InvalidArg *> parsed_and_invalid{arenaAllocator};
  missing.reserve(missing_or_invalid.size());
  for (const auto &pair : missing_or_invalid) {
    const auto &[k, v] = pair;
    switch (k.kind) {
    case ArgumentErrorKind::Missing:
      missing.push_back(v);
      break;
    case ArgumentErrorKind::InvalidInput:
      parsed_and_invalid.push_back(&pair);
      break;
    }
  }

  std::array<char, 1024> message{};
  auto it = !missing.empty() ? fmt::format_to(message.begin(), "Missing arguments: {}. ", fmt::join(missing, ", "))
                             : message.begin();

  std::array<char, 1024> invals{};
  if (!parsed_and_invalid.empty()) {
    decltype(fmt::format_to(invals.begin(), "")) inv_it;
    for (auto ref : parsed_and_invalid) {
      if (ref->first.description) {
        inv_it = fmt::format_to(invals.begin(), "{}: {}\\n", ref->second, ref->first.description.value());
      } else {
        inv_it = fmt::format_to(invals.begin(), "{}\\n", ref->second);
      }
    }

    it = fmt::format_to(it, "Invalid input for: {}", std::string_view{invals.begin(), inv_it});
  }
  *it = 0;
  std::string_view msg{message.begin(), message.begin() + std::distance(message.begin(), it)};

  std::pmr::string result{arenaAllocator};
  fmt::format_to(
    std::back_inserter(result),
    R"({{"seq":{},"request_seq":{},"type":"response","success":false,"command":"{}","message":"{}"}})", seq,
    request_seq, command, msg);

  return result;
}
} // namespace mdb::ui::dap