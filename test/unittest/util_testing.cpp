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