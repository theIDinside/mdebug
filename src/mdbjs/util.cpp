/** LICENSE TEMPLATE */
#include "./util.h"
#include "quickjs/quickjs.h"
#include <expected>

namespace mdb::js {

QuickJsString::QuickJsString(JSContext *context, const char *string) noexcept : mContext(context), mString(string)
{
}

QuickJsString::QuickJsString(QuickJsString &&other) noexcept : mContext(other.mContext), mString(nullptr)
{
  std::swap(mString, other.mString);
}

QuickJsString::~QuickJsString() noexcept
{
  if (mString) {
    JS_FreeCString(mContext, mString);
  }
}

/* static */
QuickJsString
QuickJsString::FromValue(JSContext *context, JSValue value) noexcept
{
  return QuickJsString{ context, JS_ToCString(context, value) };
}

std::expected<JSValue, QuickJsString>
CallFunction(JSContext *context, JSValue functionValue, JSValue thisValue, std::span<JSValue> arguments)
{
  JSValue returnValue = JS_Call(context, functionValue, thisValue, arguments.size(), arguments.data());
  for (const auto &v : arguments) {
    JS_FreeValue(context, v);
  }

  if (JS_IsException(returnValue)) {
    JSValue exception = JS_GetException(context);
    auto qjsString = QuickJsString::FromValue(context, exception);
    JS_FreeValue(context, exception);
    JS_FreeValue(context, returnValue);
    return std::unexpected{ std::move(qjsString) };
  }

  return std::expected<JSValue, QuickJsString>{ returnValue };
}

} // namespace mdb::js