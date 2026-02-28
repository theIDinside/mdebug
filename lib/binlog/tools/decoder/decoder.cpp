/** LICENSE TEMPLATE */
#include "decoder.h"
#include <chrono>
#include <cstring>
#include <format>
#include <fstream>
#include <iostream>
#include <regex>

namespace logdecode {

// Helper to read binary data
template <typename T>
static u32
ReadBinary(const u8 *buffer, T &value)
{
  std::memcpy(&value, buffer, sizeof(T));
  return sizeof(T);
}

// Helper to read string with u32 length prefix
static u32
ReadString(const u8 *buffer, std::string &str)
{
  u32 length;
  u32 offset = ReadBinary(buffer, length);

  if (length > 0) {
    str = std::string(reinterpret_cast<const char *>(buffer + offset), length);
    offset += length;
  } else {
    str.clear();
  }

  return offset;
}

std::string
DecodedArg::ToString() const
{
  switch (type) {
  case ArgType::SignedInt:
    return std::format("{}", std::get<i64>(value));
  case ArgType::UnsignedInt:
    return std::format("{}", std::get<u64>(value));
  case ArgType::Float:
    return std::format("{}", std::get<double>(value));
  case ArgType::Bool:
    return std::get<bool>(value) ? "true" : "false";
  case ArgType::String:
    return std::get<std::string>(value);
  case ArgType::Pointer:
    return std::format("0x{:x}", std::get<u64>(value));
  case ArgType::Enum:
    return std::format("{}", std::get<u64>(value));
  default:
    return "<unknown>";
  }
}

std::string
DecodedMessage::FormatTimestamp() const
{
  auto micros = std::chrono::microseconds(timestampUs);
  auto duration = std::chrono::duration_cast<std::chrono::system_clock::duration>(micros);
  auto timePoint = std::chrono::system_clock::time_point(duration);
  auto timeT = std::chrono::system_clock::to_time_t(timePoint);

  std::tm tm{};
  localtime_r(&timeT, &tm);

  auto us = timestampUs % 1'000'000;

  return std::format("{:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}.{:06d}",
    tm.tm_year + 1900,
    tm.tm_mon + 1,
    tm.tm_mday,
    tm.tm_hour,
    tm.tm_min,
    tm.tm_sec,
    us);
}

std::string
DecodedMessage::FormatMessage() const
{
  // Simple implementation: just replace {} with arguments in order
  std::string result = formatString;
  for (const auto &arg : args) {
    size_t pos = result.find("{}");
    if (pos != std::string::npos) {
      result.replace(pos, 2, arg.ToString());
    }
  }
  return result;
}

LogDecoder::LogDecoder(const std::filesystem::path &binaryLogPath,
  const std::filesystem::path &formatDefPath,
  const std::filesystem::path &channelNamesPath)
    : mLogPath(binaryLogPath), mFormatDefPath(formatDefPath), mChannelNamesPath(channelNamesPath)
{
  mLogFile.open(binaryLogPath, std::ios::binary);
  if (!mLogFile.is_open()) {
    throw std::runtime_error(std::format("Failed to open binary log file: {}", binaryLogPath.string()));
  }

  LoadFormatMapFromFile();

  if (!mChannelNamesPath.empty()) {
    LoadChannelNamesFromFile();
  } else {
    LoadChannelNames();
  }
}

void
LogDecoder::LoadFormatMap()
{
  // Deprecated - use LoadFormatMapFromFile()
}

void
LogDecoder::LoadFormatMapFromFile()
{
  // Parse the log_formats.def file
  // Format: LOG_FORMAT(id, "format string")

  std::ifstream defFile(mFormatDefPath);
  if (!defFile.is_open()) {
    throw std::runtime_error(std::format("Failed to open format definitions file: {}", mFormatDefPath.string()));
  }

  std::string line;
  std::regex formatRegex(R"lit(LOG_FORMAT\s*\(\s*(\d+)\s*,\s*"([^"]*)"\s*\))lit");

  while (std::getline(defFile, line)) {
    std::smatch match;
    if (std::regex_search(line, match, formatRegex)) {
      u32 id = std::stoul(match[1].str());
      std::string formatStr = match[2].str();

      // Unescape the format string
      std::string unescaped;
      for (size_t i = 0; i < formatStr.size(); ++i) {
        if (formatStr[i] == '\\' && i + 1 < formatStr.size()) {
          switch (formatStr[i + 1]) {
          case 'n':
            unescaped += '\n';
            ++i;
            break;
          case 'r':
            unescaped += '\r';
            ++i;
            break;
          case 't':
            unescaped += '\t';
            ++i;
            break;
          case '\\':
            unescaped += '\\';
            ++i;
            break;
          case '"':
            unescaped += '"';
            ++i;
            break;
          default:
            unescaped += formatStr[i];
            break;
          }
        } else {
          unescaped += formatStr[i];
        }
      }

      mFormatMap[id] = unescaped;
    }
  }

  if (mFormatMap.empty()) {
    throw std::runtime_error("No format strings found in definitions file");
  }
}

void
LogDecoder::LoadChannelNamesFromFile()
{
  // Parse the channel names file
  // Format: CHANNEL(id, "name")

  std::ifstream channelFile(mChannelNamesPath);
  if (!channelFile.is_open()) {
    throw std::runtime_error(std::format("Failed to open channel names file: {}", mChannelNamesPath.string()));
  }

  std::string line;
  std::regex channelRegex(R"lit(CHANNEL\s*\(\s*(\d+)\s*,\s*"([^"]*)"\s*\))lit");

  while (std::getline(channelFile, line)) {
    std::smatch match;
    if (std::regex_search(line, match, channelRegex)) {
      u8 id = static_cast<u8>(std::stoul(match[1].str()));
      std::string name = match[2].str();
      mChannelNames[id] = name;
    }
  }

  if (mChannelNames.empty()) {
    std::cerr << "Warning: No channel names found in file, using numeric fallback\n";
  }
}

void
LogDecoder::LoadChannelNames()
{
  // Fallback channel names (hardcoded defaults)
  // Used when no channel names file is provided
  mChannelNames[0] = "core";
  mChannelNames[1] = "control";
  mChannelNames[2] = "dap";
  mChannelNames[3] = "dwarf";
  mChannelNames[4] = "awaiter";
  mChannelNames[5] = "eh";
  mChannelNames[6] = "remote";
  mChannelNames[7] = "warning";
  mChannelNames[8] = "interpreter";
}

DecodedArg
LogDecoder::DecodeArg(const u8 *buffer, u32 &offset)
{
  DecodedArg arg;

  // Read type tag
  arg.type = static_cast<ArgType>(buffer[offset++]);

  switch (arg.type) {
  case ArgType::Bool: {
    arg.value = (buffer[offset++] != 0);
    break;
  }
  case ArgType::SignedInt: {
    u64 raw;
    offset += ReadBinary(buffer + offset, raw);
    arg.value = *reinterpret_cast<i64 *>(&raw);
    break;
  }
  case ArgType::UnsignedInt:
  case ArgType::Pointer:
  case ArgType::Enum: {
    u64 value;
    offset += ReadBinary(buffer + offset, value);
    arg.value = value;
    break;
  }
  case ArgType::Float: {
    u64 raw;
    offset += ReadBinary(buffer + offset, raw);
    arg.value = *reinterpret_cast<double *>(&raw);
    break;
  }
  case ArgType::String: {
    std::string str;
    offset += ReadString(buffer + offset, str);
    arg.value = std::move(str);
    break;
  }
  }

  return arg;
}

DecodedMessage
LogDecoder::DecodeMessage(const u8 *buffer, u32 &offset)
{
  DecodedMessage msg;

  // Read header
  msg.channel = buffer[offset++];
  offset += ReadBinary(buffer + offset, msg.formatId);
  offset += ReadBinary(buffer + offset, msg.timestampUs);
  offset += ReadBinary(buffer + offset, msg.sequenceNumber);
  offset += ReadBinary(buffer + offset, msg.threadId);
  offset += ReadString(buffer + offset, msg.fileName);
  offset += ReadBinary(buffer + offset, msg.lineNumber);
  u32 argCount = 0;
  offset += ReadBinary(buffer + offset, argCount);

  // Lookup format string
  if (auto it = mFormatMap.find(msg.formatId); it != mFormatMap.end()) {
    msg.formatString = it->second;
  } else {
    msg.formatString = std::format("<unknown format id {}>", msg.formatId);
  }

  // Lookup channel name
  if (auto it = mChannelNames.find(msg.channel); it != mChannelNames.end()) {
    msg.channelName = it->second;
  } else {
    msg.channelName = std::format("<channel {}>", static_cast<int>(msg.channel));
  }

  // Read arguments
  msg.args.reserve(argCount);
  for (u8 i = 0; i < argCount; ++i) {
    msg.args.push_back(DecodeArg(buffer, offset));
  }

  return msg;
}

void
LogDecoder::FormatAsText(std::ostream &out, const DecodedMessage &msg)
{
  out << '[' << msg.sequenceNumber << "] " << msg.FormatTimestamp() << " [TID:" << msg.threadId << "] ["
      << msg.channelName << "] " << msg.FormatMessage() << " [" << msg.fileName << ":" << msg.lineNumber << "]\n";
}

void
LogDecoder::FormatAsJSON(std::ostream &out, const DecodedMessage &msg)
{
  out << "{\n"
      << R"(  "sequence": )" << msg.sequenceNumber << ",\n"
      << R"(  "timestamp": ")" << msg.FormatTimestamp() << "\",\n"
      << R"(  "thread_id": )" << msg.threadId << ",\n"
      << R"(  "channel": ")" << msg.channelName << "\",\n"
      << R"(  "message": ")" << msg.FormatMessage() << "\",\n"
      << R"(  "file": ")" << msg.fileName << "\",\n"
      << R"(  "line": )" << msg.lineNumber << "\n"
      << "}\n";
}

void
LogDecoder::Decode(std::ostream &out)
{
  // Read entire file into memory
  mLogFile.seekg(0, std::ios::end);
  auto fileSize = mLogFile.tellg();
  mLogFile.seekg(0, std::ios::beg);

  std::vector<u8> buffer(fileSize);
  mLogFile.read(reinterpret_cast<char *>(buffer.data()), fileSize);

  if (!mLogFile) {
    throw std::runtime_error("Failed to read binary log file");
  }

  // Decode all messages
  u32 offset = 0;
  bool firstMessage = true;

  if (mOutputFormat == OutputFormat::JSON) {
    out << "[\n";
  }

  while (offset < buffer.size()) {
    auto msg = DecodeMessage(buffer.data(), offset);

    // Apply channel filter
    if (mHasChannelFilter && msg.channel != mFilterChannel) {
      continue;
    }

    if (mOutputFormat == OutputFormat::JSON) {
      if (!firstMessage) {
        out << ",\n";
      }
      firstMessage = false;
    }

    if (mOutputFormat == OutputFormat::Text) {
      FormatAsText(out, msg);
    } else {
      FormatAsJSON(out, msg);
    }
  }

  if (mOutputFormat == OutputFormat::JSON) {
    out << "\n]\n";
  }
}

} // namespace logdecode
