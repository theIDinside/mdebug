/** LICENSE TEMPLATE */
#pragma once

// mdb
#include "common/typedefs.h"
#include "quickjs.h"

// std
#include <string_view>

struct JSContext;
struct JSValue;

namespace mdb::js {

struct StackValue
{
  JSContext *mContext;
  JSValue mValue;

  StackValue(JSContext *cx, JSValue value) noexcept;
  StackValue(StackValue &&) noexcept;
  StackValue &operator=(StackValue &&) noexcept;
  ~StackValue() noexcept;

  StackValue(StackValue &) = delete;
  StackValue &operator=(const StackValue &) = delete;

  StackValue GetPropertyUint32(u32 index) const;
  StackValue GetPropertyString(const char *string) const;
  StackValue ToString() const;

  JSValue Throw();
  JSValue Release();
  static StackValue ToString(JSContext *cx, JSValue value);
  static StackValue GetGlobal(JSContext *cx);
  static StackValue Wrap(JSContext *cx, JSValue value);
  static StackValue NewUint32(JSContext *cx, u32 value);
  static StackValue NewInt32(JSContext *cx, int value);
  static StackValue GetPropertyString(JSContext *cx, JSValue value, const char *string);
  static StackValue Eval(
    JSContext *cx, const char *input, size_t inputLength, const char *file, int evalFlags = JS_EVAL_TYPE_GLOBAL);

  operator JSValue &() { return mValue; }
};

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