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
  std::string_view mString{};

  QuickJsString() noexcept = default;
  QuickJsString(JSContext *context, const char *string) noexcept;
  QuickJsString(QuickJsString &&) noexcept;
  QuickJsString &operator=(QuickJsString &&) noexcept;

  QuickJsString(const QuickJsString &) = delete;

  QuickJsString &operator=(const QuickJsString &) = delete;

  ~QuickJsString() noexcept;

  static QuickJsString FromValue(JSContext *context, JSValue value) noexcept;

private:
  void Release() noexcept;
};

}; // namespace mdb::js