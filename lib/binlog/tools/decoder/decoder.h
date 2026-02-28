/** LICENSE TEMPLATE */
#pragma once
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

namespace logdecode {

using u8 = std::uint8_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using i64 = std::int64_t;

enum class ArgType : u8
{
  SignedInt = 1,
  UnsignedInt = 2,
  Float = 3,
  Bool = 4,
  String = 5,
  Pointer = 6,
  Enum = 7,
};

struct DecodedArg
{
  ArgType type;
  std::variant<i64, u64, double, bool, std::string> value;

  std::string ToString() const;
};

struct DecodedMessage
{
  u8 channel;
  std::string channelName;
  u32 formatId;
  std::string formatString;
  u64 timestampUs;
  u64 sequenceNumber;
  u32 threadId;
  std::string fileName;
  u32 lineNumber;
  std::vector<DecodedArg> args;

  std::string FormatMessage() const;
  std::string FormatTimestamp() const;
};

class LogDecoder
{
public:
  enum class OutputFormat
  {
    Text,
    JSON
  };

  explicit LogDecoder(const std::filesystem::path &binaryLogPath,
    const std::filesystem::path &formatDefPath,
    const std::filesystem::path &channelNamesPath = {});

  void
  SetOutputFormat(OutputFormat format) noexcept
  {
    mOutputFormat = format;
  }
  void
  SetChannelFilter(u8 channel) noexcept
  {
    mFilterChannel = channel;
    mHasChannelFilter = true;
  }

  void Decode(std::ostream &out);

private:
  std::filesystem::path mLogPath;
  std::filesystem::path mFormatDefPath;
  std::filesystem::path mChannelNamesPath;
  std::ifstream mLogFile;
  std::unordered_map<u32, std::string> mFormatMap;
  std::unordered_map<u8, std::string> mChannelNames;
  OutputFormat mOutputFormat{ OutputFormat::Text };
  bool mHasChannelFilter{ false };
  u8 mFilterChannel{ 0 };

  void LoadFormatMap();
  void LoadFormatMapFromFile();
  void LoadChannelNamesFromFile();
  void LoadChannelNames();
  DecodedMessage DecodeMessage(const u8 *buffer, u32 &offset);
  DecodedArg DecodeArg(const u8 *buffer, u32 &offset);
  void FormatAsText(std::ostream &out, const DecodedMessage &msg);
  void FormatAsJSON(std::ostream &out, const DecodedMessage &msg);
};

} // namespace logdecode
