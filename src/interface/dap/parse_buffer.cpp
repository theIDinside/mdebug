#include "parse_buffer.h"
#include <charconv>

namespace ui::dap {

static const std::regex content_length = std::regex{R"(Content-Length: (\d+)\s{4})"};

std::vector<ContentParse>
parse_buffer(const std::string_view buffer_view, bool *all_msgs_ok) noexcept
{
  std::vector<ContentParse> result;

  std::smatch m;
  std::string_view internal_view{buffer_view};
  ViewMatchResult base_match;
  bool partial_found = false;
  while (std::regex_search(internal_view.begin(), internal_view.end(), base_match, content_length)) {
    if (base_match.size() == 2) {
      std::sub_match<std::string_view::const_iterator> base_sub_match = base_match[1];
      std::string_view len_str{base_sub_match.first, base_sub_match.second};
      u64 len;
      const auto res = std::from_chars(len_str.data(), len_str.data() + len_str.size(), len);
      if (res.ec != std::errc()) {
        PANIC(fmt::format("Hard failure if <regex> thinks it's found a number when it didn't"));
      }
      ASSERT(res.ec != std::errc(), "Failed to parse Content Length {}", len_str);
      if (base_match.position() + base_match.length() + len <= internal_view.size()) {
        result.push_back(ContentDescriptor{.payload_length = len,
                                           .header_begin = internal_view.data() + base_match.position(),
                                           .payload_begin = internal_view.data() + base_match.length()});
        internal_view.remove_prefix(base_match.position() + base_match.length() + len);
      } else {
        result.push_back(PartialContentDescriptor{
            .payload_length = len,
            .payload_missing = (base_match.position() + base_match.length() + len) - internal_view.size(),
            .payload_begin = internal_view.data() + base_match.position() + base_match.length()});
        internal_view.remove_prefix(internal_view.size());
        partial_found = true;
      }
    }
  }
  if (!internal_view.empty()) {
    result.push_back(RemainderData{.length = internal_view.size(), .begin = internal_view.data()});
    partial_found = true;
  }
  if (all_msgs_ok != nullptr)
    *all_msgs_ok = !partial_found;
  return result;
}
} // namespace ui::dap