#include <array>
#include <gtest/gtest.h>
#include <string_view>
#include <utils/expected.h>

struct Destructible
{
  static int destroyed_n_times;
  static int moved_from_cnt;
  static int copy_ctor;
  static int constructed_by_move_params;
  static int normal_ctor;
  bool moved_from = false;
  Destructible(std::string data) : data(std::move(data))
  {
    // normal ctor
    normal_ctor++;
  }

  Destructible(const Destructible &o) : data(o.data)
  {
    // copy ctor
    copy_ctor++;
  }

  Destructible(Destructible &&o) : data(std::move(o.data))
  {
    moved_from_cnt++;
    o.moved_from = true;
  }

  ~Destructible() noexcept
  {
    if (!moved_from)
      destroyed_n_times++;
  }
  std::string data;
};

int Destructible::destroyed_n_times = 0;
int Destructible::moved_from_cnt = 0;
int Destructible::constructed_by_move_params = 0;
int Destructible::normal_ctor = 0;
int Destructible::copy_ctor = 0;

TEST(Expected, TestTrivialTypes) {}

static utils::Expected<Destructible, int>
take_chars_must_have_len(const std::string &s, unsigned count)
{
  if (s.size() > count) {
    auto str = s.substr(0, count);
    return utils::Expected<Destructible, int>{str};
  } else {
    return utils::unexpected(static_cast<int>(count - s.size()));
  }
}

static utils::Expected<std::array<std::string, 4>, int>
create_substrs(const std::string &s, unsigned count)
{
  if (s.size() > count) {
    std::array<std::string, 4> res;
    auto str = s.substr(0, count);
    res[0] = str;
    res[1] = str;
    res[2] = str;
    res[3] = str;
    return utils::expected(std::move(res));
  } else {
    return utils::unexpected<int>(static_cast<int>(count - s.size()));
  }
}

TEST(Expected, TestNonTrivialT)
{
  std::string str = "hello world";
  for (auto i = 7; i < 11; ++i) {
    auto sub = take_chars_must_have_len(str, i);
    EXPECT_TRUE(sub.is_expected());
    Destructible foo{sub.value()};
  }

  for (auto i = 7; i < 11; ++i) {
    // should trigger Destructible move ctor
    Destructible foo{take_chars_must_have_len(str, i).value()};
  }

  EXPECT_EQ(Destructible::destroyed_n_times, 12);
  EXPECT_EQ(Destructible::moved_from_cnt, 4);
  EXPECT_EQ(Destructible::copy_ctor, Destructible::moved_from_cnt);
  EXPECT_EQ(Destructible::normal_ctor, 8);

  for (auto i = 12; i < 15; ++i) {
    auto sub = take_chars_must_have_len(str, i);
    EXPECT_TRUE(!sub.is_expected());
  }

  for (auto i = 7; i < 15; ++i) {
    auto foo = create_substrs(str, i);
    if (i < 11) {
      EXPECT_TRUE(foo.is_expected());
    } else if (i > 11) {
      EXPECT_TRUE(!foo.is_expected());
    }
  }

  // EXPECT_EQ(Destructible::destroyed_n_times, 4);
}

TEST(Expected, TestNonTrivialErr) {}
TEST(Expected, TestNonTrivial) {}