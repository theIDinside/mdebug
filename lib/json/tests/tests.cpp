#include <gtest/gtest.h>
#include <json/json.h>
#include <memory_resource>
#include <print>
#include <string_view>

static std::byte BigChunkArray[4096 * 32];

struct TestMemoryResource : public std::pmr::memory_resource
{
  std::pmr::monotonic_buffer_resource upstream{ BigChunkArray, std::size(BigChunkArray) };

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
  mdbjson::JsonValue val = result.value();
  EXPECT_TRUE(val.IsBoolean());
  EXPECT_EQ(*val.GetBoolean(), true);
}

TEST(JsonParseTests, ParseNumber)
{
  TestMemoryResource mem;
  auto result = mdbjson::Parse(&mem, "42");
  ASSERT_TRUE(result.has_value());
  mdbjson::JsonValue val = result.value();
  EXPECT_TRUE(val.IsNumber());
  EXPECT_DOUBLE_EQ(*val.GetNumber(), 42.0);
}

TEST(JsonParseTests, ParseString)
{
  TestMemoryResource mem;
  auto result = mdbjson::Parse(&mem, "\"hello\"");
  ASSERT_TRUE(result.has_value());
  mdbjson::JsonValue val = result.value();
  EXPECT_TRUE(val.IsString());
  EXPECT_EQ(*val.GetString(), "hello");
}

TEST(JsonParseTests, ParseArray)
{
  TestMemoryResource mem;
  auto result = mdbjson::Parse(&mem, "[1,2,3]");
  ASSERT_TRUE(result.has_value());
  mdbjson::JsonValue val = result.value();
  EXPECT_TRUE(val.IsArray());
  auto arr = val.GetArray();
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
  mdbjson::JsonValue val = result.value();
  EXPECT_TRUE(val.IsObject());

  auto propStr = val.At("key");
  ASSERT_NE(propStr, nullptr);
  EXPECT_TRUE(propStr->IsString());
  EXPECT_EQ(*propStr->GetString(), "value");

  auto propNum = val.At("num");
  ASSERT_NE(propNum, nullptr);
  EXPECT_TRUE(propNum->IsNumber());
  EXPECT_DOUBLE_EQ(*propNum->GetNumber(), 123.0);
}

TEST(JsonParseTests, ParseAndCheckSubProperties)
{
  TestMemoryResource mem;
  auto result = mdbjson::Parse(&mem,
    R"({
      "key": "value",
      "num": 123,
      "subObjectOne": {
        "array": [
          "The world is a dark and very cruel place to live in.\nThis should be on a new line.",
          42,
          "mixed strings and numbers in an array? Is that not crazy work?"
        ],
        "success": true
      },
      "subObjectTwo": {
        "value": null,
        "wasOk": false,
        "message": "This is a public service announcement, brought to you, in part, by Slim Shady. The views and events expressed here are totally fucked (Yeah) and are not necessarily the views of anyone."
      }
    })");
  if (!result.has_value()) {
  }
  ASSERT_TRUE(result.has_value());
  mdbjson::JsonValue val = result.value();
  EXPECT_TRUE(val.IsObject());

  auto keyProperty = val.At("key");
  ASSERT_NE(keyProperty, nullptr);
  EXPECT_TRUE(keyProperty->IsString());
  EXPECT_EQ(*keyProperty->GetString(), "value");

  auto numProperty = val.At("num");
  ASSERT_NE(numProperty, nullptr);
  EXPECT_TRUE(numProperty->IsNumber());
  EXPECT_DOUBLE_EQ(*numProperty->GetNumber(), 123.0);

  // Sub object 1
  {
    auto subObj1 = val.At("subObjectOne");
    ASSERT_NE(subObj1, nullptr);
    EXPECT_TRUE(subObj1->IsObject());

    auto s1ArrayJson = subObj1->At("array");
    ASSERT_NE(s1ArrayJson, nullptr);
    EXPECT_TRUE(s1ArrayJson->IsArray());
    const auto &s1Array = *s1ArrayJson->GetArray();
    EXPECT_EQ(s1Array.size(), 3);
    EXPECT_TRUE(s1Array[0].IsString());
    EXPECT_TRUE(s1Array[1].IsNumber());
    EXPECT_TRUE(s1Array[2].IsString());

    EXPECT_EQ(*s1Array[0].GetString(),
      "The world is a dark and very cruel place to live in.\nThis should be on a new line.");
    std::print("string={}\n", *s1Array[0].GetString());
    EXPECT_EQ(*s1Array[1].GetNumber(), 42);
    EXPECT_EQ(*s1Array[2].GetString(), "mixed strings and numbers in an array? Is that not crazy work?");

    auto successProp = subObj1->At("success");
    auto success = successProp->GetBoolean();
    EXPECT_NE(success, nullptr);
    EXPECT_TRUE(*success);
  }

  auto subObj2 = val.At("subObjectTwo");
  ASSERT_NE(subObj2, nullptr);
  EXPECT_TRUE(subObj2->IsObject());
}

TEST(JsonParseTests, ParseInvalidJson)
{
  TestMemoryResource mem;
  auto result = mdbjson::Parse(&mem, "{invalid}");
  EXPECT_FALSE(result.has_value());
  EXPECT_EQ(result.error().mKind, mdbjson::ParseError::ErrorKind::UnexpectedCharacter);
}