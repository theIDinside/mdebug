#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <string>
#include <type_traits>

#include "../../src/interface/dap/parse_buffer.h"

// clang-format off
const auto WellFormedPayloads_3 = 
R"(Content-Length: 145)" "\r\n\r\n" 
R"({"seq":1,"type":"request","command":"launch","arguments":{"program":"/home/cx/dev/foss/cx/midas/test/cppworkspace/bin/test","stopOnEntry":false}})"
R"(Content-Length: 74)"
"\r\n\r\n"
R"({"seq":2,"type":"request","command":"continue","arguments":{"threadId":1}})"
R"(Content-Length: 233)"
"\r\n\r\n"
R"({"seq":3,"type":"request","command":"setDataBreakpoints","arguments":{"breakpoints":[{"description":"type info or message why couldn't be set","dataId":"foo.bar","accessTypes":["read","write","readWrite"],"accessType":"readWrite"}]}})";

const auto OneWellFormedOnePartial = 
R"(Content-Length: 145)" "\r\n\r\n" 
R"({"seq":1,"type":"request","command":"launch","arguments":{"program":"/home/cx/dev/foss/cx/midas/test/cppworkspace/bin/test","stopOnEntry":false}})"
R"(Content-Length: 74)"
"\r\n\r\n"
R"({"seq":2,"type":"request","command":"continue","arguments":{"threadId":1)";

const auto OneWellFormedOneRemainderData = 
R"(Content-Length: 145)" "\r\n\r\n" 
R"({"seq":1,"type":"request","command":"launch","arguments":{"program":"/home/cx/dev/foss/cx/midas/test/cppworkspace/bin/test","stopOnEntry":false}})"
R"(Content-Length: )";

// clang-format on

TEST(DapRequestParsing, WellFormedPayloadsTest)
{
  std::byte pmr_buffer[1028];
  std::pmr::monotonic_buffer_resource descriptor_resource{&pmr_buffer, sizeof(pmr_buffer)};
  const auto result = ui::dap::parse_headers_from(WellFormedPayloads_3, descriptor_resource);
  EXPECT_EQ(result.size(), 3);
}

TEST(DapRequestParsing, CorrectHeaderTypes)
{
  std::byte pmr_buffer[1028];
  std::pmr::monotonic_buffer_resource descriptor_resource{&pmr_buffer, sizeof(pmr_buffer)};
  const auto result = ui::dap::parse_headers_from(WellFormedPayloads_3, descriptor_resource);
  for (auto &&data : result) {
    EXPECT_EQ(data.index(), 0);
  }
}

using ContentParse =
    std::variant<ui::dap::ContentDescriptor, ui::dap::PartialContentDescriptor, ui::dap::RemainderData>;

using CD = ui::dap::ContentDescriptor;
using PCD = ui::dap::PartialContentDescriptor;
using RD = ui::dap::RemainderData;

TEST(DapRequestParsing, CorrectMixOfHeaderTypes)
{
  std::byte pmr_buffer[1028];
  std::pmr::monotonic_buffer_resource descriptor_resource{&pmr_buffer, sizeof(pmr_buffer)};
  const auto result = ui::dap::parse_headers_from(OneWellFormedOnePartial, descriptor_resource);
  EXPECT_EQ(result.size(), 2);
  EXPECT_EQ(result[0].index(), 0);
  EXPECT_EQ(result[1].index(), 1);
  std::visit(
      [&](auto &&item) {
        using T = ActualType<decltype(item)>;
        if constexpr (std::is_same_v<T, PCD>) {
          FAIL() << "Did not expect Partial Content Descriptor";
        } else if constexpr (std::is_same_v<T, CD>) {
          EXPECT_EQ(item.payload_length, 145);
        } else if constexpr (std::is_same_v<T, RD>) {
          FAIL() << "Type expected was 'ContentDescriptor' with length 145: not Remainder Data";
        } else {
          FAIL() << "Failed to determine type. WTF?"
                 << " type index: " << result[0].index();
        }
      },
      result[0]);

  std::visit(
      [](auto &item) {
        using T = ActualType<decltype(item)>;
        constexpr auto ExpectedMissing = 2;
        if constexpr (std::is_same_v<T, PCD>) {
          EXPECT_EQ(item.payload_missing, ExpectedMissing)
              << "Expected " << ExpectedMissing << " bytes missing but got " << item.payload_missing;
        } else if constexpr (std::is_same_v<T, CD>) {
          FAIL() << "Type should not be ui::dap::ContentDescriptor";
        } else {
          FAIL() << "Type should not be ui::dap::RemainderData";
        }
      },
      result[1]);
}

TEST(DapRequestParsing, OneWellFormedOneRemainderData)
{
  std::byte pmr_buffer[1028];
  std::pmr::monotonic_buffer_resource descriptor_resource{&pmr_buffer, sizeof(pmr_buffer)};
  const auto result = ui::dap::parse_headers_from(OneWellFormedOneRemainderData, descriptor_resource);
  EXPECT_EQ(result.size(), 2);
  EXPECT_EQ(result[0].index(), 0);
  EXPECT_EQ(result[1].index(), 2);
  auto cd = maybe_unwrap<CD>(result[0]);
  EXPECT_TRUE(cd != nullptr) << "Expected type to be Content Descriptor";
  EXPECT_EQ(cd->payload_length, 145);

  const RD *rd = maybe_unwrap<RD>(result[1]);
  EXPECT_TRUE(rd != nullptr) << "Expected type to be Remainder Data";
  EXPECT_EQ(rd->length, 16);
}

TEST(DapRequestParsing, ParseRequestTypes3WellFormed)
{
  std::byte pmr_buffer[1028];
  std::pmr::monotonic_buffer_resource descriptor_resource{&pmr_buffer, sizeof(pmr_buffer)};
  const auto result = ui::dap::parse_headers_from(WellFormedPayloads_3, descriptor_resource);
  const auto unwrapper = [](const auto &v) -> const CD * { return maybe_unwrap<CD>(v); };
  auto i = 0;
  for (auto &&payload : result) {
    auto ptr = unwrapper(payload);
    EXPECT_TRUE(ptr != nullptr) << "Expected payload to be OK parsed";
    std::string_view data{ptr->payload_begin, ptr->payload_begin + ptr->payload_length};
    fmt::println("payload contents: '{}'", data);
    auto json = nlohmann::json::parse(data);
    EXPECT_TRUE(json["command"].is_string());
    std::string_view cmd_str;
    json.at("command").get_to(cmd_str);
    const auto command = ui::dap::parse_command_type(cmd_str);
    switch (i++) {
    case 0:
      EXPECT_EQ(ui::dap::CommandType::Launch, command)
          << "Expected Launch but got " << to_str(command) << " from str " << cmd_str;
      break;
    case 1:
      EXPECT_EQ(ui::dap::CommandType::Continue, command)
          << "Expected Continue but got " << to_str(command) << " from str " << cmd_str;
      break;
    case 2:
      EXPECT_EQ(ui::dap::CommandType::SetDataBreakpoints, command)
          << "Expected SetDataBreakpoints but got " << to_str(command) << " from str " << cmd_str;
      break;
    }
  }
}

const auto SetInsBkptReq =
    R"(Content-Length: 205)"
    "\r\n\r\n"
    R"({"seq":4,"type":"request","command":"setInstructionBreakpoints","arguments":{"breakpoints":[{"instructionReference":"0x402030"},{"instructionReference":"0x7ffffff"},{"instructionReference":"0xabcdbeef"}]}})";

TEST(DapRequestParsing, setInstructionBreakpointsParsing)
{
  std::byte pmr_buffer[1028];
  std::pmr::monotonic_buffer_resource descriptor_resource{&pmr_buffer, sizeof(pmr_buffer)};
  const auto result = ui::dap::parse_headers_from(SetInsBkptReq, descriptor_resource);
  const auto unwrapper = [](const auto &v) -> const CD * { return maybe_unwrap<CD>(v); };
  auto ptr = unwrapper(result[0]);
  EXPECT_TRUE(ptr != nullptr) << "Expected payload to be OK parsed";
  std::string_view data{ptr->payload_begin, ptr->payload_begin + ptr->payload_length};
  auto json = nlohmann::json::parse(data);
  EXPECT_TRUE(json["command"].is_string());
  std::string_view cmd_str;
  json.at("command").get_to(cmd_str);
  const auto command = ui::dap::parse_command_type(cmd_str);
  EXPECT_EQ(command, ui::dap::CommandType::SetInstructionBreakpoints);
  std::string_view cmd_name;
  json["command"].get_to(cmd_name);
  ASSERT(json.contains("arguments"), "Request did not contain an 'arguments' field: {}", packet);
}