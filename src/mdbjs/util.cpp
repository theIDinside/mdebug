/** LICENSE TEMPLATE */
#include "./util.h"

// mdb
#include <utils/logger.h>
#include <utils/scope_defer.h>

// dependency
#include <mdbjs/include-quickjs.h>

namespace mdb::js {

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