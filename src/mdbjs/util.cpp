/** LICENSE TEMPLATE */
#include "./util.h"

// mdb
#include <utils/logger.h>
#include <utils/scope_defer.h>

// dependency
#include <mdbjs/include-quickjs.h>

namespace mdb::js {

StackValue::StackValue(JSContext *cx, JSValue value) noexcept : mContext(cx), mValue(value) {}

StackValue::StackValue(StackValue &&other) noexcept
{
  mContext = other.mContext;
  mValue = other.mValue;
  other.mContext = nullptr;
}

StackValue &
StackValue::operator=(StackValue &&other) noexcept
{
  if (this != &other) {
    mContext = other.mContext;
    mValue = other.mValue;
    other.mContext = nullptr;
  }

  return *this;
}

StackValue::~StackValue() noexcept
{
  if (mContext) {
    JS_FreeValue(mContext, mValue);
  }
}

StackValue
StackValue::GetPropertyUint32(u32 index) const
{
  return StackValue::Wrap(mContext, JS_GetPropertyUint32(mContext, mValue, index));
}

JSValue
StackValue::Throw()
{
  mContext = nullptr;
  return mValue;
}

/* static */
StackValue
StackValue::Wrap(JSContext *cx, JSValue value)
{
  return StackValue{ cx, value };
}

/* static */
StackValue
StackValue::NewUint32(JSContext *cx, u32 value)
{
  return StackValue{ cx, JS_NewUint32(cx, value) };
}

/* static */
StackValue
StackValue::NewInt32(JSContext *cx, int value)
{
  return StackValue{ cx, JS_NewInt32(cx, value) };
}

// static
StackValue
StackValue::GetPropertyString(JSContext *cx, JSValue value, const char *string)
{
  return Wrap(cx, JS_GetPropertyStr(cx, value, string));
}

/* static */
StackValue
StackValue::Eval(JSContext *cx, const char *input, size_t inputLength, const char *file, int evalFlags)
{
  return StackValue::Wrap(cx, JS_Eval(cx, input, inputLength, file, evalFlags));
}

void
QuickJsString::Release() noexcept
{
  if (!mString.empty()) {
    JS_FreeCString(mContext, mString.data());
  }
  mString = std::string_view{};
}

QuickJsString::QuickJsString(JSContext *context, const char *string) noexcept : mContext(context), mString(string)
{
}

QuickJsString::QuickJsString(QuickJsString &&other) noexcept : mContext(other.mContext), mString()
{
  std::swap(mString, other.mString);
}

QuickJsString &
QuickJsString::operator=(QuickJsString &&rhs) noexcept
{
  if (this != &rhs) {
    Release();
    mContext = rhs.mContext;
    std::swap(mString, rhs.mString);
  }
  return *this;
}

QuickJsString::~QuickJsString() noexcept { Release(); }

/* static */
QuickJsString
QuickJsString::FromValue(JSContext *context, JSValue value) noexcept
{
  return QuickJsString{ context, JS_ToCString(context, value) };
}

} // namespace mdb::js