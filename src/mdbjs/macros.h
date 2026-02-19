/** LICENSE TEMPLATE */
#pragma once

#define DECLARE_METHOD(Method, ...)                                                                               \
  static JSValue Method(JSContext *cx, JSValueConst thisValue, int argCount, JSValueConst *argv) noexcept;