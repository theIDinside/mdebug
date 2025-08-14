/** LICENSE TEMPLATE */
#pragma once

#include "mdbjs/jsobject.h"
#include "symbolication/value.h"
#include <common/typedefs.h>

namespace mdb::js {

struct JsVariable : public JSBinding<JsVariable, sym::Value, JavascriptClasses::Variable>
{
  static auto Id(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  static auto Name(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  static auto ToString(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  static auto TypeName(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  static auto Address(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  static auto Dereference(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  static auto Bytes(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  static auto IsLive(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  static auto SetValue(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  static auto CacheLayout(JSContext *context, sym::Value *value) noexcept -> void;

  /** Gets member variable when user does foo.mMember or foo.value, foo.blah, etc. As such, when user reads
   * property, it uses the get_property functionality in QuickJS. If the backing sym::Type* does not have a member
   * called .bar, we throw an exception because the idea is that the user probably expected to read a type it
   * thought and now it's not having that member, it's better to make noise than silently fail with JS_UNDEFINED.*/
  static auto GetMemberVariable(
    JSContext *context, JSValueConst thisValue, JSAtom prop, JSValueConst receiverValue) noexcept -> JSValue;

  static constexpr std::span<const JSCFunctionListEntry>
  PrototypeFunctions() noexcept
  {
    static constexpr auto fns = std::to_array({ /** Method definitions */
      FunctionEntry("id", 0, &Id),
      FunctionEntry("name", 0, &Name),
      FunctionEntry("toString", 1, &ToString),
      FunctionEntry("typeName", 0, &TypeName),
      FunctionEntry("address", 0, &Address),
      FunctionEntry("dereference", 0, &Dereference),
      FunctionEntry("bytes", 0, &Bytes),
      FunctionEntry("isLive", 0, &IsLive),
      FunctionEntry("setValue", 1, &SetValue),
      ToStringTag("Variable") });
    return fns;
  }

  static consteval auto
  ExoticMethods() noexcept -> JSClassExoticMethods
  {
    JSClassExoticMethods v{};
    v.get_property = &GetMemberVariable;
    return v;
  }
};

} // namespace mdb::js