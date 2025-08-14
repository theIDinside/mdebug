/** LICENSE TEMPLATE */
#pragma once

#include "quickjs/quickjs.h"
#include <expected>
#include <span>

namespace mdb::js {

struct QuickJsString
{
  JSContext *mContext;
  const char *mString;

  QuickJsString(JSContext *context, const char *string) noexcept;
  QuickJsString(QuickJsString &&) noexcept;

  QuickJsString(const QuickJsString &) = delete;

  QuickJsString &operator=(const QuickJsString &) = delete;
  QuickJsString &operator=(QuickJsString &&) = delete;

  ~QuickJsString() noexcept;

  static QuickJsString FromValue(JSContext *context, JSValue value) noexcept;
};

/** Calls function `functionValue` and then frees the arguments in `arguments`. */
std::expected<JSValue, QuickJsString> CallFunction(
  JSContext *context, JSValue functionValue, JSValue thisValue, std::span<JSValue> consumedArguments);

}; // namespace mdb::js