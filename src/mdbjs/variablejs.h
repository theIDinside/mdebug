/** LICENSE TEMPLATE */
#pragma once

// mdb
#include <common/typedefs.h>
#include <mdbjs/jsobject.h>
#include <symbolication/value.h>

namespace mdb::js {

struct JsType : public JSBinding<JsType, sym::Type, JavascriptClasses::Type>
{
  static auto Name(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  static auto ToString(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  // Returns the number of bytes this type takes up.
  static auto SizeOf(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  // Look up member with name `name` and return its JsType
  static auto Member(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  // Return all the members JsType's in an array
  static auto Members(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  static auto ToPrimitive(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  static auto PointeeSize(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  static auto TemplateArgument(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;

  static constexpr std::span<const JSCFunctionListEntry>
  PrototypeFunctions() noexcept
  {
    static constexpr auto fns = std::to_array({ /** Method definitions */
      FunctionEntry("name", 0, &Name),
      FunctionEntry("toString", 0, &ToString),
      FunctionEntry("sizeOf", 0, &SizeOf),
      FunctionEntry("pointeeSize", 0, &PointeeSize),
      FunctionEntry("member", 1, &Member),
      FunctionEntry("members", 0, &Members),
      FunctionEntry("templateArgument", 1, &TemplateArgument),
      ToStringTag("Type") });
    return fns;
  }

  static constexpr auto
  DefineToPrimitive(JSContext *cx, JSValue prototype, JSAtom toPrimitiveAtom)
  {
    MDB_ASSERT(toPrimitiveAtom != 0, "toPrimitive atom must be passed to function");
    JSValue func = JS_NewCFunction(cx, &ToPrimitive, "[[toPrimitive]]", 1);
    int rc = JS_DefinePropertyValue(cx,
      prototype,
      toPrimitiveAtom,
      func,
      JS_PROP_C_W_E); // Configurable + Writeable + Enumerable
    MDB_ASSERT(rc != -1 && rc > 0, "Defining the toPrimitive property failed.");
    JS_FreeAtom(cx, toPrimitiveAtom);
  }
};

struct JsVariable : public JSBinding<JsVariable, sym::Value, JavascriptClasses::Variable>
{
  static auto Id(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  static auto Name(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  static auto ToString(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  static auto TypeName(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  static auto Address(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  static auto Dereference(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  static auto Bytes(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  static auto IsLive(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  static auto SetValue(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  static auto ToPrimitive(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  static auto Type(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  static auto Member(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  static auto Members(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;
  static auto MemberCount(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;

  // Note, should (in time) turn a type T* to a T[]. If you have a type T* and you want an array of pointers,
  // you need to first promote, to T **, then .asArray -> T*[]
  static auto AsArray(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv) noexcept -> JSValue;

  /** Gets member variable when user does foo.mMember or foo.value, foo.blah, etc. As such, when user reads
   * property, it uses the get_property functionality in QuickJS. If the backing sym::Type* does not have a member
   * called .bar, we throw an exception because the idea is that the user probably expected to read a type it
   * thought and now it's not having that member, it's better to make noise than silently fail with JS_UNDEFINED.*/
  static auto GetMemberVariable(
    JSContext *cx, JSValueConst thisValue, JSAtom prop, JSValueConst receiverValue) noexcept -> JSValue;

  static constexpr std::span<const JSCFunctionListEntry>
  PrototypeFunctions() noexcept
  {
    static constexpr auto fns = std::to_array({ /** Method definitions */
      FunctionEntry("id", 0, &Id),
      FunctionEntry("name", 0, &Name),
      FunctionEntry("toString", 1, &ToString),
      FunctionEntry("typeName", 0, &TypeName),
      FunctionEntry("address", 0, &Address),
      FunctionEntry("deref", 1, &Dereference),
      FunctionEntry("bytes", 0, &Bytes),
      FunctionEntry("isLive", 0, &IsLive),
      FunctionEntry("setValue", 1, &SetValue),
      FunctionEntry("member", 1, &Member),
      FunctionEntry("members", 0, &Members),
      FunctionEntry("asArray", 1, &AsArray),
      FunctionEntry("type", 0, &Type),
      FunctionEntry("memberCount", 0, &MemberCount),
      ToStringTag("Variable") });
    return fns;
  }

  static constexpr auto
  ExoticMethods() noexcept -> JSClassExoticMethods *
  {
    static JSClassExoticMethods v{};
    v.get_property = &GetMemberVariable;
    return &v;
  }

  static constexpr auto
  DefineToPrimitive(JSContext *cx, JSValue prototype, JSAtom toPrimitiveAtom)
  {
    MDB_ASSERT(toPrimitiveAtom != 0, "toPrimitive atom must be passed to function");
    JSValue func = JS_NewCFunction(cx, &ToPrimitive, "[[toPrimitive]]", 1);
    int rc = JS_DefinePropertyValue(cx,
      prototype,
      toPrimitiveAtom,
      func,
      JS_PROP_C_W_E); // Configurable + Writeable + Enumerable
    MDB_ASSERT(rc != -1 && rc > 0, "Defining the toPrimitive property failed.");
    JS_FreeAtom(cx, toPrimitiveAtom);
  }
};

} // namespace mdb::js