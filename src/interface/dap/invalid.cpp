/** LICENSE TEMPLATE */
#include "invalid.h"

// system
#include <array>
#include <format>

namespace mdb::ui::dap {
InvalidArgsResponse::InvalidArgsResponse(
  Pid processId, std::string_view command, MissingOrInvalidArgs &&missing_args) noexcept
    : UIResult(processId), mProcessId(processId), command(command), missing_or_invalid(std::move(missing_args))
{
}

std::pmr::string
InvalidArgsResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::vector<std::string_view> missing{ arenaAllocator };
  std::pmr::vector<const InvalidArg *> parsedAndInvalid{ arenaAllocator };
  missing.reserve(missing_or_invalid.size());
  for (const auto &pair : missing_or_invalid) {
    const auto &[k, v] = pair;
    switch (k.kind) {
    case ArgumentErrorKind::Missing:
      missing.push_back(v);
      break;
    case ArgumentErrorKind::InvalidInput:
      parsedAndInvalid.push_back(&pair);
      break;
    }
  }

  std::pmr::string result{ arenaAllocator };
  auto formatIter = std::format_to(std::back_inserter(result),
    R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":false,"command":"{}","message":"Invalid request made. Arguments missing or of invalid type.", "body": {{)",
    seq,
    mRequestSeq,
    mProcessId,
    command);

  bool wrote = false;
  if (!missing.empty()) {
    formatIter = std::format_to(formatIter, R"("missing": [)");
    for (const auto m : missing) {
      if (wrote) {
        *formatIter++ = ',';
      }
      formatIter = std::format_to(formatIter, R"("{}")", m);
      wrote = true;
    }
    *formatIter++ = ']';
  }

  if (!parsedAndInvalid.empty()) {
    if (wrote) {
      *formatIter++ = ',';
    }
    wrote = false;
    formatIter = std::format_to(formatIter, R"("errors": {{)");
    for (auto ref : parsedAndInvalid) {
      if (wrote) {
        *formatIter++ = ',';
      }
      formatIter =
        std::format_to(formatIter, R"("{}":"{}")", ref->second, ref->first.description.value_or("unknown error"));
      wrote = true;
    }
    *formatIter++ = '}';
  }

  *formatIter++ = '}';
  *formatIter++ = '}';
  return result;
}
} // namespace mdb::ui::dap