/** LICENSE TEMPLATE */
#pragma once

// std
#include <string_view>

struct JSContext;
struct JSValue;

namespace mdb::js {

struct QuickJsString
{

  JSContext *mContext{ nullptr };
  std::string_view mString{ nullptr, 0 };

  QuickJsString() noexcept = default;
  QuickJsString(JSContext *context, const char *string) noexcept;
  QuickJsString(QuickJsString &&) noexcept;
  QuickJsString &operator=(QuickJsString &&) noexcept;

  QuickJsString(const QuickJsString &) = delete;

  QuickJsString &operator=(const QuickJsString &) = delete;

  ~QuickJsString() noexcept;

  static QuickJsString FromValue(JSContext *context, JSValue value) noexcept;

  template <typename StringType>
  friend bool
  operator==(const QuickJsString &lhs, const StringType &rhs)
  {
    return lhs == rhs;
  }

  template <typename StringType>
  friend bool
  operator==(const StringType &rhs, const QuickJsString &lhs)
  {
    return lhs == rhs;
  }

private:
  void Release() noexcept;
};

}; // namespace mdb::js