/** LICENSE TEMPLATE */
#include "parse_buffer.h"

namespace mdb::ui::dap {

static const std::regex CONTENT_LENGTH_HEADER = std::regex{ R"(Content-Length: (\d+)\r\n\r\n)" };

std::vector<ContentParse>
ParseHeadersFromBuffer(std::string_view bufferView, bool *allMessagesOk) noexcept
{
  std::vector<ContentParse> result;

  std::smatch m;
  std::string_view internalView{ bufferView };
  ViewMatchResult base_match;
  bool partial_found = false;
  while (std::regex_search(internalView.begin(), internalView.end(), base_match, CONTENT_LENGTH_HEADER)) {
    if (base_match.size() == 2) {
      std::sub_match<std::string_view::const_iterator> base_sub_match = base_match[1];
      std::string_view len_str{ base_sub_match.first, base_sub_match.second };
      const auto res = to_integral<u64>(len_str);
      MDB_ASSERT(res.has_value(), "Failed to parse length from Content-Length header");
      const auto len = res.value();
      if (base_match.position() + base_match.length() + len <= internalView.size()) {
        const auto *headerBeginPtr = internalView.data() + base_match.position();
        const auto *payloadBeginPtr = headerBeginPtr + base_match.length();
        const u64 packet_offset =
          static_cast<u64>(std::distance((const char *)bufferView.data(), (const char *)headerBeginPtr));
        result.emplace_back(ContentDescriptor{ .mPayloadLength = len,
          .mPacketOffset = packet_offset,
          .mHeaderBegin = headerBeginPtr,
          .mPayloadBegin = payloadBeginPtr });
        internalView.remove_prefix(base_match.position() + base_match.length() + len);
      } else {
        result.emplace_back(PartialContentDescriptor{ .mPayloadLength = len,
          .mPayloadMissing = (base_match.position() + base_match.length() + len) - internalView.size(),
          .mPayloadBegin = internalView.data() + base_match.position() + base_match.length() });
        internalView.remove_prefix(internalView.size());
        partial_found = true;
      }
    }
  }
  if (!internalView.empty()) {
    const char *ptr = internalView.data();
    const char *begin = bufferView.data();
    const u64 offset = std::distance(begin, ptr);
    result.emplace_back(RemainderData{ .mLength = internalView.size(), .mOffset = offset });
    partial_found = true;
  }
  if (allMessagesOk != nullptr) {
    *allMessagesOk = !partial_found;
  }
  return result;
}
} // namespace mdb::ui::dap