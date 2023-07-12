#include "parse_buffer.h"
#include <charconv>
#include <fstream>
namespace ui::dap {

static const std::regex CONTENT_LENGTH_HEADER = std::regex{R"(Content-Length: (\d+)\s{2})"};

static std::fstream *logger_file = nullptr;

void
setup_logging(std::fstream &logger)
{
  logger_file = &logger;
}

inline void
log_if(std::string_view msg) noexcept
{
  if (logger_file) {
    auto &stream = *logger_file;
    stream << msg << "\n" << std::flush;
  }
}

#define LOG_IF(fmt_expression)                                                                                    \
  if (logger_file) {                                                                                              \
    auto &stream = *logger_file;                                                                                  \
    stream << (fmt_expression) << "\n" << std::flush;                                                             \
  }

std::vector<ContentParse>
parse_headers_from(const std::string_view buffer_view, bool *all_msgs_ok) noexcept
{
  std::vector<ContentParse> result;

  std::smatch m;
  std::string_view internal_view{buffer_view};
  ViewMatchResult base_match;
  bool partial_found = false;
  while (std::regex_search(internal_view.begin(), internal_view.end(), base_match, CONTENT_LENGTH_HEADER)) {
    if (base_match.size() == 2) {
      std::sub_match<std::string_view::const_iterator> base_sub_match = base_match[1];
      std::string_view len_str{base_sub_match.first, base_sub_match.second};
      const auto res = to_integral<u64>(len_str);
      ASSERT(res.has_value(), "Failed to parse length from Content-Length header");
      const auto len = res.value();
      if (base_match.position() + base_match.length() + len <= internal_view.size()) {
        const auto header_begin_ptr = internal_view.data() + base_match.position();
        const auto payload_begin_ptr = header_begin_ptr + base_match.length();
        const auto packet_offset =
            static_cast<u64>(std::distance((const char *)buffer_view.data(), (const char *)header_begin_ptr));
        LOG_IF(fmt::format("payload length: '{}'\nHeader begins at '{}'", len_str, base_match.position()));
        result.push_back(ContentDescriptor{.payload_length = len,
                                           .packet_offset = packet_offset,
                                           .header_begin = header_begin_ptr,
                                           .payload_begin = payload_begin_ptr});
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
    const char *ptr = internal_view.data();
    const char *begin = buffer_view.data();
    const u64 offset = std::distance(begin, ptr);
    LOG_IF(fmt::format("Remainder data length {} at offset {}", internal_view.size(), offset));
    result.push_back(RemainderData{.length = internal_view.size(), .offset = offset});
    partial_found = true;
  }
  if (all_msgs_ok != nullptr)
    *all_msgs_ok = !partial_found;
  return result;
}
} // namespace ui::dap