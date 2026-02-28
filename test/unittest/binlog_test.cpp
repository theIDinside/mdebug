#include <binlog/encoding.h>
#include <binlog/logger.h>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <string_view>

using namespace binlog;

// Test fixture for binary encoding tests
class BinaryEncodingTest : public ::testing::Test
{
protected:
  u8 buffer[1024];

  void
  SetUp() override
  {
    std::memset(buffer, 0, sizeof(buffer));
  }
};

// Test encoding and decoding of various integer types
TEST_F(BinaryEncodingTest, EncodeDecodeSignedIntegers)
{
  i64 original = -42;
  u32 offset = 0;

  // Encode
  offset += BinaryWriter::WriteByte(buffer + offset, static_cast<u8>(ArgType::SignedInt));
  offset += BinaryWriter::Write64(buffer + offset, *reinterpret_cast<u64 *>(&original));

  // Decode
  offset = 0;
  u8 type;
  offset += BinaryReader::ReadByte(buffer + offset, type);
  EXPECT_EQ(static_cast<ArgType>(type), ArgType::SignedInt);

  u64 raw;
  offset += BinaryReader::Read64(buffer + offset, raw);
  i64 decoded = *reinterpret_cast<i64 *>(&raw);

  EXPECT_EQ(decoded, original);
}

TEST_F(BinaryEncodingTest, EncodeDecodeUnsignedIntegers)
{
  u64 original = 12345678901234ULL;
  u32 offset = 0;

  // Encode
  offset += BinaryWriter::WriteByte(buffer + offset, static_cast<u8>(ArgType::UnsignedInt));
  offset += BinaryWriter::Write64(buffer + offset, original);

  // Decode
  offset = 0;
  u8 type;
  offset += BinaryReader::ReadByte(buffer + offset, type);
  EXPECT_EQ(static_cast<ArgType>(type), ArgType::UnsignedInt);

  u64 decoded;
  offset += BinaryReader::Read64(buffer + offset, decoded);

  EXPECT_EQ(decoded, original);
}

TEST_F(BinaryEncodingTest, EncodeDecodeFloats)
{
  double original = 3.141592653589793;
  u32 offset = 0;

  // Encode
  offset += BinaryWriter::WriteByte(buffer + offset, static_cast<u8>(ArgType::Float));
  offset += BinaryWriter::Write64(buffer + offset, *reinterpret_cast<u64 *>(&original));

  // Decode
  offset = 0;
  u8 type;
  offset += BinaryReader::ReadByte(buffer + offset, type);
  EXPECT_EQ(static_cast<ArgType>(type), ArgType::Float);

  u64 raw;
  offset += BinaryReader::Read64(buffer + offset, raw);
  double decoded = *reinterpret_cast<double *>(&raw);

  EXPECT_DOUBLE_EQ(decoded, original);
}

TEST_F(BinaryEncodingTest, EncodeDecodeBool)
{
  bool original = true;
  u32 offset = 0;

  // Encode
  offset += BinaryWriter::WriteByte(buffer + offset, static_cast<u8>(ArgType::Bool));
  offset += BinaryWriter::WriteByte(buffer + offset, original ? 1 : 0);

  // Decode
  offset = 0;
  u8 type;
  offset += BinaryReader::ReadByte(buffer + offset, type);
  EXPECT_EQ(static_cast<ArgType>(type), ArgType::Bool);

  u8 value;
  offset += BinaryReader::ReadByte(buffer + offset, value);
  bool decoded = (value != 0);

  EXPECT_EQ(decoded, original);
}

TEST_F(BinaryEncodingTest, EncodeDecodeString)
{
  std::string_view original = "Hello, Binary Logging!";
  u32 offset = 0;

  // Encode
  offset += BinaryWriter::WriteByte(buffer + offset, static_cast<u8>(ArgType::String));
  offset += BinaryWriter::WriteString(buffer + offset, original);

  // Decode
  offset = 0;
  u8 type;
  offset += BinaryReader::ReadByte(buffer + offset, type);
  EXPECT_EQ(static_cast<ArgType>(type), ArgType::String);

  std::string_view decoded;
  offset += BinaryReader::ReadString(buffer + offset, decoded);

  EXPECT_EQ(decoded, original);
}

TEST_F(BinaryEncodingTest, EncodeDecodePointer)
{
  void *original = reinterpret_cast<void *>(0xDEADBEEF);
  u64 addr = reinterpret_cast<u64>(original);
  u32 offset = 0;

  // Encode
  offset += BinaryWriter::WriteByte(buffer + offset, static_cast<u8>(ArgType::Pointer));
  offset += BinaryWriter::Write64(buffer + offset, addr);

  // Decode
  offset = 0;
  u8 type;
  offset += BinaryReader::ReadByte(buffer + offset, type);
  EXPECT_EQ(static_cast<ArgType>(type), ArgType::Pointer);

  u64 decoded_addr;
  offset += BinaryReader::Read64(buffer + offset, decoded_addr);

  EXPECT_EQ(decoded_addr, addr);
}

TEST_F(BinaryEncodingTest, EncodeEmptyString)
{
  std::string_view original = "";
  u32 offset = 0;

  // Encode
  offset += BinaryWriter::WriteByte(buffer + offset, static_cast<u8>(ArgType::String));
  offset += BinaryWriter::WriteString(buffer + offset, original);

  // Decode
  offset = 0;
  u8 type;
  offset += BinaryReader::ReadByte(buffer + offset, type);

  std::string_view decoded;
  offset += BinaryReader::ReadString(buffer + offset, decoded);

  EXPECT_EQ(decoded, original);
  EXPECT_TRUE(decoded.empty());
}

TEST_F(BinaryEncodingTest, EncodeLongString)
{
  std::string original(5000, 'X'); // 5KB string
  u32 offset = 0;

  // Encode
  offset += BinaryWriter::WriteByte(buffer, static_cast<u8>(ArgType::String));

  // For long strings, we need a bigger buffer
  std::vector<u8> large_buffer(10000);
  offset = 0;
  offset += BinaryWriter::WriteByte(large_buffer.data() + offset, static_cast<u8>(ArgType::String));
  offset += BinaryWriter::WriteString(large_buffer.data() + offset, original);

  // Decode
  offset = 0;
  u8 type;
  offset += BinaryReader::ReadByte(large_buffer.data() + offset, type);

  std::string_view decoded;
  offset += BinaryReader::ReadString(large_buffer.data() + offset, decoded);

  EXPECT_EQ(decoded, original);
  EXPECT_EQ(decoded.size(), 5000);
}

// Test type detection
TEST(TypeDetectionTest, GetArgTypeForIntegers)
{
  EXPECT_EQ(GetArgType<i8>(), ArgType::SignedInt);
  EXPECT_EQ(GetArgType<i16>(), ArgType::SignedInt);
  EXPECT_EQ(GetArgType<i32>(), ArgType::SignedInt);
  EXPECT_EQ(GetArgType<i64>(), ArgType::SignedInt);

  EXPECT_EQ(GetArgType<u8>(), ArgType::UnsignedInt);
  EXPECT_EQ(GetArgType<u16>(), ArgType::UnsignedInt);
  EXPECT_EQ(GetArgType<u32>(), ArgType::UnsignedInt);
  EXPECT_EQ(GetArgType<u64>(), ArgType::UnsignedInt);
}

TEST(TypeDetectionTest, GetArgTypeForFloats)
{
  EXPECT_EQ(GetArgType<float>(), ArgType::Float);
  EXPECT_EQ(GetArgType<double>(), ArgType::Float);
}

TEST(TypeDetectionTest, GetArgTypeForBool) { EXPECT_EQ(GetArgType<bool>(), ArgType::Bool); }

TEST(TypeDetectionTest, GetArgTypeForString)
{
  EXPECT_EQ(GetArgType<std::string_view>(), ArgType::String);
  EXPECT_EQ(GetArgType<const char *>(), ArgType::String);
  EXPECT_EQ(GetArgType<std::string>(), ArgType::String);
}

TEST(TypeDetectionTest, GetArgTypeForPointer)
{
  EXPECT_EQ(GetArgType<void *>(), ArgType::Pointer);
  EXPECT_EQ(GetArgType<int *>(), ArgType::Pointer);
  EXPECT_EQ(GetArgType<const char *const>(), ArgType::Pointer);
}

// Test message encoding
TEST(MessageEncodingTest, EncodeSimpleMessage)
{
  u8 buffer[1024];
  std::memset(buffer, 0, sizeof(buffer));

  u8 channel = 0;
  u32 formatId = 42;
  u64 timestamp = 1234567890000ULL;
  u64 seqNum = 1;
  u32 threadId = 5678;
  std::string_view fileName = "test.cpp";
  u32 lineNumber = 100;

  u32 bytesWritten = BinaryLogEncoder::EncodeMessage(
    buffer, channel, formatId, timestamp, seqNum, threadId, fileName, lineNumber, 123, "test");

  EXPECT_GT(bytesWritten, 0);

  // Verify we can read back the header
  u32 offset = 0;
  u8 decoded_channel;
  offset += BinaryReader::ReadByte(buffer + offset, decoded_channel);
  EXPECT_EQ(decoded_channel, channel);

  u32 decoded_formatId;
  std::memcpy(&decoded_formatId, buffer + offset, sizeof(u32));
  offset += sizeof(u32);
  EXPECT_EQ(decoded_formatId, formatId);

  u64 decoded_timestamp;
  offset += BinaryReader::Read64(buffer + offset, decoded_timestamp);
  EXPECT_EQ(decoded_timestamp, timestamp);
}

TEST(MessageEncodingTest, EncodeMessageWithMultipleArgs)
{
  u8 buffer[1024];
  std::memset(buffer, 0, sizeof(buffer));

  u32 bytesWritten =
    BinaryLogEncoder::EncodeMessage(buffer, 0, 1, 1000ULL, 1, 123, "file.cpp", 50, 42, 3.14, "hello", true, -99);

  EXPECT_GT(bytesWritten, 0);
  EXPECT_LT(bytesWritten, sizeof(buffer)); // Should fit in buffer
}

// Test BinaryLogger integration
class BinaryLoggerTest : public ::testing::Test
{
protected:
  std::filesystem::path testLogPath;

  void
  SetUp() override
  {
    // Create temp directory for test logs
    testLogPath = std::filesystem::temp_directory_path() / "binlog_test.bin";
    // Remove if exists from previous test
    std::filesystem::remove(testLogPath);
  }

  void
  TearDown() override
  {
    // Cleanup
    std::filesystem::remove(testLogPath);
  }
};

TEST_F(BinaryLoggerTest, CreateAndShutdown)
{
  BinaryLogger::Config config{ .logFilePath = testLogPath };

  {
    BinaryLogger logger(config);
    logger.Shutdown();
  }

  // Verify log file was created
  EXPECT_TRUE(std::filesystem::exists(testLogPath));
}

TEST_F(BinaryLoggerTest, LogSingleMessage)
{
  BinaryLogger::Config config{ .logFilePath = testLogPath };

  {
    BinaryLogger logger(config);
    logger.Log(0, 1, std::source_location::current(), 42, "test");
    logger.Shutdown();
  }

  // Verify log file has content
  EXPECT_TRUE(std::filesystem::exists(testLogPath));
  auto fileSize = std::filesystem::file_size(testLogPath);
  EXPECT_GT(fileSize, 0);
}

TEST_F(BinaryLoggerTest, LogMultipleMessages)
{
  BinaryLogger::Config config{ .logFilePath = testLogPath };

  {
    BinaryLogger logger(config);

    for (int i = 0; i < 100; ++i) {
      logger.Log(0, 1, std::source_location::current(), i, "message", 3.14);
    }

    logger.Shutdown();
  }

  // Verify log file has substantial content
  EXPECT_TRUE(std::filesystem::exists(testLogPath));
  auto fileSize = std::filesystem::file_size(testLogPath);
  EXPECT_GT(fileSize, 100); // At least 1 byte per message
}

TEST_F(BinaryLoggerTest, ThreadLocalBufferFlush)
{
  BinaryLogger::Config config{ .logFilePath = testLogPath };

  {
    BinaryLogger logger(config);

    // Log many messages to trigger flush
    for (int i = 0; i < 1000; ++i) {
      logger.Log(0, 1, std::source_location::current(), i);
    }

    logger.Shutdown();
  }

  EXPECT_TRUE(std::filesystem::exists(testLogPath));
}

// Test edge cases
TEST(EdgeCaseTest, ZeroValues)
{
  u8 buffer[256];
  u32 offset = 0;

  // Encode zero
  offset += BinaryWriter::WriteByte(buffer + offset, static_cast<u8>(ArgType::SignedInt));
  i64 zero = 0;
  offset += BinaryWriter::Write64(buffer + offset, *reinterpret_cast<u64 *>(&zero));

  // Decode
  offset = 0;
  u8 type;
  offset += BinaryReader::ReadByte(buffer + offset, type);

  u64 raw;
  offset += BinaryReader::Read64(buffer + offset, raw);
  i64 decoded = *reinterpret_cast<i64 *>(&raw);

  EXPECT_EQ(decoded, 0);
}

TEST(EdgeCaseTest, MaxValues)
{
  u8 buffer[256];
  u32 offset = 0;

  // Encode max u64
  u64 max_val = UINT64_MAX;
  offset += BinaryWriter::WriteByte(buffer + offset, static_cast<u8>(ArgType::UnsignedInt));
  offset += BinaryWriter::Write64(buffer + offset, max_val);

  // Decode
  offset = 0;
  u8 type;
  offset += BinaryReader::ReadByte(buffer + offset, type);

  u64 decoded;
  offset += BinaryReader::Read64(buffer + offset, decoded);

  EXPECT_EQ(decoded, max_val);
}

TEST(EdgeCaseTest, NegativeValues)
{
  u8 buffer[256];
  u32 offset = 0;

  i64 negative = -9223372036854775807LL; // Near min i64
  offset += BinaryWriter::WriteByte(buffer + offset, static_cast<u8>(ArgType::SignedInt));
  offset += BinaryWriter::Write64(buffer + offset, *reinterpret_cast<u64 *>(&negative));

  // Decode
  offset = 0;
  u8 type;
  offset += BinaryReader::ReadByte(buffer + offset, type);

  u64 raw;
  offset += BinaryReader::Read64(buffer + offset, raw);
  i64 decoded = *reinterpret_cast<i64 *>(&raw);

  EXPECT_EQ(decoded, negative);
}
