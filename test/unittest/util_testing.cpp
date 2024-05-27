#include "utils/expected.h"
#include <gtest/gtest.h>
#include <set>
#include <string_view>
#include <utils/enumerator.h>
#include <utils/filter.h>
#include <utils/interval_map.h>
#include <utils/skiperator.h>
#include <utils/util.h>

TEST(IntervalMap, IsConsistentWithOverlappingRanges) {}

TEST(Enumerator, IsConsistentWithOverlappingRanges) {}

TEST(Skiperator, IsConsistentWithOverlappingRanges) {}

TEST(Filter, IsConsistentWithOverlappingRanges) {}

testing::AssertionResult
SetContains(std::set<std::string_view> expected_set, std::string_view test)
{
  if (expected_set.contains(test))
    return testing::AssertionSuccess();
  else {
    std::stringstream ss{};
    ss << "Set [";
    auto i = 0u;
    for (const auto item : expected_set) {
      ss << item << ((++i != expected_set.size()) ? ", " : "]");
    }
    return testing::AssertionFailure() << ss.str() << " does not contain '" << test << "'";
  }
}

TEST(StringSplit, CommaSeparated)
{
  std::string foo = "eh,dwarf,dap,";
  std::set<std::string_view> expected{"eh", "dwarf", "dap"};
  auto res = utils::split_string(foo, ",");
  EXPECT_EQ(res.size(), expected.size());
  std::set<std::string_view> res_set{res.begin(), res.end()};
  for (const auto item : res_set) {
    EXPECT_TRUE(SetContains(expected, item));
  }
}

TEST(GdbRemote, DecodeNonRunLengthEncodedData) {}

static constexpr std::string_view registerPacket2 =
    R"(08e1fff7ff7f0*!8e1fff7ff7f0* d4d5f*"7f0*"d0fff7ff7f0*@b0d8f*"7f0*"d6f*"7f0*"bafff7ff7f0*!f0**c0d5f*"7f0* 46020*(c0e2fff7ff7f0* b0dafff7ff7f0* c0e2fff7ff7f0*0c47bfef7ff7f0*!6020* 330*"2b0*}0*}0* 7f030*(f* 0*Nf*"00ff00ff00ff00ff00f*"ff00010100010001000100010001415445005f5f6c6962635f6561726c79410*:5445005f5f6c6962635f6561726c795f8037cbf7ff7f0* 705fcbf7ff7f0* 480*:705dcbf7ff7f0* e05fcbf7ff7f0*}0*}0*^801f0* f*,4047e9f7ff7f0*}0*}0*}0*}0*}0*K)";

static constexpr std::string_view decoded =
    R"(08e1fff7ff7f000008e1fff7ff7f0000d4d5ffffff7f000000d0fff7ff7f000000000000000000000000000000000000b0d8ffffff7f000000d6ffffff7f000000bafff7ff7f00000f00000000000000c0d5ffffff7f00004602000000000000c0e2fff7ff7f0000b0dafff7ff7f0000c0e2fff7ff7f00000000000000000000c47bfef7ff7f000006020000330000002b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007f03000000000000ffff00000000000000000000000000000000000000000000000000ffffff00ff00ff00ff00ff00ffffffff00010100010001000100010001415445005f5f6c6962635f6561726c79410000000000000000000000000000005445005f5f6c6962635f6561726c795f8037cbf7ff7f0000705fcbf7ff7f000048000000000000000000000000000000705dcbf7ff7f0000e05fcbf7ff7f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000801f0000ffffffffffffffff4047e9f7ff7f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000)";

TEST(GdbRemote, DecodeGPacket)
{
  std::array<u8, 816> buf{};
  utils::deserialize_hex_encoded(registerPacket2, buf);
  std::array<u8, 816> buf2{};
  std::string_view v = decoded;
  auto i = 0;
  while (!v.empty()) {
    buf2[i] = (utils::fromhex(v[0]) << 4) | utils::fromhex(v[1]);
    v.remove_prefix(2);
    ++i;
  }

  EXPECT_EQ(buf, buf2);
}

TEST(GdbRemote, RunLengthDecode)
{
  std::string_view contents{"48888ffffffa0000"};
  std::string_view encoded{"48* fff* a0* "};
  std::array<u8, 8> val_non_encoded{};
  std::array<u8, 8> val_encoded{};

  utils::deserialize_hex_encoded(contents, val_non_encoded);
  utils::deserialize_hex_encoded(encoded, val_encoded);

  for (auto i = 0u; i < val_encoded.size(); ++i) {
    EXPECT_EQ(val_encoded[i], val_non_encoded[i]);
  }
}