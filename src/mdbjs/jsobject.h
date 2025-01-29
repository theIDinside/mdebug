/** LICENSE TEMPLATE */
#pragma once

#include "js/Class.h"
#include "js/GCTypeMacros.h"
#include "js/Object.h"
#include "js/TypeDecls.h"
#include "jsapi.h"
#include "utils/smartptr.h"
namespace mdb::js {

template <typename DerivedJsObject> concept HasJsLayout = requires { DerivedJsObject::ThisPointer; };

template <typename T> concept HasTraceFunction = requires(T t, JSTracer *trc) { t.trace(trc); };

template <typename T>
concept DefinesProperties = requires(JSContext *cx, JSObject *obj) { T::DefineProperties(cx, obj); };

template <typename T>
concept DefinesFunctions = requires(JSContext *cx, JSObject *obj) { T::DefinesFunctions(cx, obj); };

// Eventually we'll life this constraint IsRefPointer<T>, and instead specialize internally for cases where
// T is IsRefPointer and where it's not (and also rename the class).
template <typename Derived, IsRefCountable WrappedType, StringLiteral string> struct RefPtrJsObject
{
  // Unfortunately we can't pass WrappedType via Derived. Oh my lord meta programming and compile time programming
  // in C++ is trash, 40 years later.
  using Self = RefPtrJsObject<Derived, WrappedType, string>;
  using SelfJs = Derived;
  using RefPtr = Ref<WrappedType>;

  static constexpr const char *Name = string.CString();

  // When a CustomObject is traced, it must trace the stored box.
  static constexpr void
  TraceSubobjects(JSTracer *trc, JSObject *obj) noexcept
    requires(HasTraceFunction<Derived>)
  {
    FromObject(obj)->trace(trc);
  }

  static constexpr void
  RefPtrFinalize(JS::GCContext *gcx, JSObject *thisJs) noexcept
  {
    Untraced<WrappedType>{JS::GetMaybePtrFromReservedSlot<WrappedType>(thisJs, Derived::ThisPointer)}.Drop();
  }

  static consteval auto
  DetermineFinalizeOp()
  {
    static_assert(Derived::ThisPointer == 0, "This pointer slot must exist");
    return RefPtrFinalize;
  }

  static consteval auto
  DetermineTraceFunction() noexcept
  {
    if constexpr (HasTraceFunction<Derived>) {
      return TraceSubobjects;
    }
    return nullptr;
  }

  static constexpr JSClassOps classOps = {.finalize = DetermineFinalizeOp(), .trace = DetermineTraceFunction()};

  static constexpr JSClass clasp = {.name = Name,
                                    .flags =
                                      JSCLASS_HAS_RESERVED_SLOTS(Derived::SlotCount) | JSCLASS_FOREGROUND_FINALIZE,
                                    .cOps = &classOps};

  static JSObject *
  Create(JSContext *cx, const RefPtr &object) noexcept
  {
    auto tmp = RefPtr{object};
    return Create(cx, std::move(tmp));
  }

  static JSObject *
  Create(JSContext *cx, RefPtr &&object) noexcept
  {
    JS::Rooted<JSObject *> obj(cx, JS_NewObject(cx, &clasp));
    if (!obj) {
      return nullptr;
    }
    JS_SetReservedSlot(obj, Derived::ThisPointer, JS::PrivateValue(std::move(object).DisOwn().Forget()));

    if constexpr (requires(Derived d, JSContext *cx, JSObject *obj) { Derived::DefineProperties(cx, obj); }) {
      Derived::DefineProperties(cx, obj.get());
    }

    if constexpr (requires(Derived d, JSContext *cx, JSObject *obj) { Derived::FunctionSpec; }) {
      JS_DefineFunctions(cx, obj, Derived::FunctionSpec);
    }

    return obj;
  }

  constexpr RefPtr
  Get() noexcept
  {
    JSObject *thisJs = Self::AsObject(this);
    Untraced<WrappedType> pObj{JS::GetMaybePtrFromReservedSlot<WrappedType>(thisJs, Derived::ThisPointer)};
    return pObj.Take();
  }

  static constexpr RefPtr
  Get(JSObject *This) noexcept
  {
    Untraced<WrappedType> pObj{JS::GetMaybePtrFromReservedSlot<WrappedType>(This, Derived::ThisPointer)};
    return pObj.Take();
  }

  // Full type of JSObject is not known, so we can't inherit.
  static Derived *
  FromObject(JSObject *obj)
  {
    return reinterpret_cast<Derived *>(obj);
  }

  static JSObject *
  AsObject(Derived *obj)
  {
    return reinterpret_cast<JSObject *>(obj);
  }
};
} // namespace mdb::js

#define JS_METHOD(METHOD_NAME) static bool METHOD_NAME(JSContext *cx, unsigned argc, JS::Value *vp) noexcept