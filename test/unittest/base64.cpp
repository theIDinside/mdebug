#include <gtest/gtest.h>
#include <string>

#include "../../src/utils/base64.h"

TEST(Base64Encoding, Encoding)
{
  std::uint8_t values[] = { 71, 73, 70 };
  const auto res = mdb::EncodeBase64(values);
  EXPECT_EQ(res, "R0lG");
}