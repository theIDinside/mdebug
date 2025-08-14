#include <gtest/gtest.h>
#include <json/json.h>
#include <memory_resource>
#include <string_view>

struct TestMemoryResource : public std::pmr::memory_resource
{
  std::pmr::monotonic_buffer_resource upstream{};

protected:
  void *
  do_allocate(size_t bytes, size_t alignment) override
  {
    return upstream.allocate(bytes, alignment);
  }
  void
  do_deallocate(void *p, size_t bytes, size_t alignment) override
  {
    upstream.deallocate(p, bytes, alignment);
  }
  bool
  do_is_equal(const std::pmr::memory_resource &other) const noexcept override
  {
    return this == &other;
  }
};

TEST(JsonParseTests, ParseBooleanTrue)
{
  TestMemoryResource mem;
  auto result = mdbjson::Parse(&mem, "true");
  ASSERT_TRUE(result.has_value());
  mdbjson::JsonValue *val = result.value();
  EXPECT_TRUE(val->IsBoolean());
  EXPECT_EQ(*val->GetBoolean(), true);
}

TEST(JsonParseTests, ParseNumber)
{
  TestMemoryResource mem;
  auto result = mdbjson::Parse(&mem, "42");
  ASSERT_TRUE(result.has_value());
  mdbjson::JsonValue *val = result.value();
  EXPECT_TRUE(val->IsNumber());
  EXPECT_DOUBLE_EQ(*val->GetNumber(), 42.0);
}

TEST(JsonParseTests, ParseString)
{
  TestMemoryResource mem;
  auto result = mdbjson::Parse(&mem, "\"hello\"");
  ASSERT_TRUE(result.has_value());
  mdbjson::JsonValue *val = result.value();
  EXPECT_TRUE(val->IsString());
  EXPECT_EQ(*val->GetString(), "hello");
}

TEST(JsonParseTests, ParseArray)
{
  TestMemoryResource mem;
  auto result = mdbjson::Parse(&mem, "[1,2,3]");
  ASSERT_TRUE(result.has_value());
  mdbjson::JsonValue *val = result.value();
  EXPECT_TRUE(val->IsArray());
  auto arr = val->GetArray();
  ASSERT_NE(arr, nullptr);
  ASSERT_EQ(arr->size(), 3u);
  EXPECT_DOUBLE_EQ(*(*arr)[0].GetNumber(), 1.0);
  EXPECT_DOUBLE_EQ(*(*arr)[1].GetNumber(), 2.0);
  EXPECT_DOUBLE_EQ(*(*arr)[2].GetNumber(), 3.0);
}

TEST(JsonParseTests, ParseObjectAndGetProperty)
{
  TestMemoryResource mem;
  auto result = mdbjson::Parse(&mem, R"({"key": "value", "num": 123})");
  ASSERT_TRUE(result.has_value());
  mdbjson::JsonValue *val = result.value();
  EXPECT_TRUE(val->IsObject());

  auto propStr = val->GetProperty("key");
  ASSERT_NE(propStr, nullptr);
  EXPECT_TRUE(propStr->IsString());
  EXPECT_EQ(*propStr->GetString(), "value");

  auto propNum = val->GetProperty("num");
  ASSERT_NE(propNum, nullptr);
  EXPECT_TRUE(propNum->IsNumber());
  EXPECT_DOUBLE_EQ(*propNum->GetNumber(), 123.0);
}

TEST(JsonParseTests, ParseInvalidJson)
{
  TestMemoryResource mem;
  auto result = mdbjson::Parse(&mem, "{invalid}");
  EXPECT_FALSE(result.has_value());
  EXPECT_EQ(result.error().mKind, mdbjson::ParseError::ErrorKind::UnexpectedCharacter);
}