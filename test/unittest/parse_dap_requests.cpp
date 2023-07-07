#include <gtest/gtest.h>
#include <type_traits>

#include "../../src/interface/dap/interface.h"

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
  const auto result = ui::dap::parse_buffer(WellFormedPayloads_3);
  EXPECT_EQ(result.size(), 3);
}

TEST(DapRequestParsing, CorrectHeaderTypes)
{
  const auto result = ui::dap::parse_buffer(WellFormedPayloads_3);
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
  const auto result = ui::dap::parse_buffer(OneWellFormedOnePartial);
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
  const auto result = ui::dap::parse_buffer(OneWellFormedOneRemainderData);
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