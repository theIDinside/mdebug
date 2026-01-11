/** LICENSE TEMPLATE */
#pragma once

#define DECLARE_METHOD(Method, ...)                                                                               \
  static JSValue Method(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) noexcept;