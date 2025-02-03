/** LICENSE TEMPLATE */
#pragma once

#include "js/Class.h"
#include "js/GCTypeMacros.h"
#include "js/Object.h"
#include "js/PropertyAndElement.h"
#include "js/PropertySpec.h"
#include "js/RootingAPI.h"
#include "js/TypeDecls.h"
#include "jsapi.h"
#include "utils/smartptr.h"
namespace mdb::js {

#define GET_THIS(name)                                                                                            \
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);                                                               \
  JS::RootedObject callee(cx, &args.thisv().toObject());                                                          \
  auto name = Get(callee.get());

template <typename DerivedJsObject> concept HasJsLayout = requires { DerivedJsObject::ThisPointer; };

template <typename T> concept HasTraceFunction = requires(T t, JSTracer *trc) { t.trace(trc); };
template <typename T>
concept HasResolve =
  requires(T t, JSContext *cx, JS::HandleId id, bool *resolved) { t.resolve(cx, id, resolved); };

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
  using Reference = Ref<WrappedType>;

  static constexpr const char *Name = string.CString();

  // When a CustomObject is traced, it must trace the stored box.
  static constexpr void
  TraceSubobjects(JSTracer *trc, JSObject *obj) noexcept
    requires(HasTraceFunction<Derived>)
  {
    FromObject(obj)->trace(trc);
  }

  static constexpr bool
  ResolveProperty(JSContext *cx, JS::HandleObject obj, JS::HandleId id, bool *resolved) noexcept
  {
    JS::Rooted<JSObject *> object{cx, obj};
    return FromObject(object)->resolve(cx, id, resolved);
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

  static consteval JSClassOps
  ClassOps() noexcept
  {
    if constexpr (HasResolve<Derived>) {
      return JSClassOps{
        .resolve = &ResolveProperty, .finalize = DetermineFinalizeOp(), .trace = DetermineTraceFunction()};
    } else {
      return JSClassOps{.resolve = nullptr, .finalize = DetermineFinalizeOp(), .trace = DetermineTraceFunction()};
    }
  }

  static constexpr JSClassOps classOps = ClassOps();

  static constexpr JSClass clasp = {.name = Name,
                                    .flags =
                                      JSCLASS_HAS_RESERVED_SLOTS(Derived::SlotCount) | JSCLASS_FOREGROUND_FINALIZE,
                                    .cOps = &classOps};

  template <typename... Args>
  static JSObject *
  Make(JSContext *cx, Args &&...args) noexcept
  {
    Create(cx, Ref<WrappedType>::MakeShared(std::forward<Args>(args)...));
  }

  template <typename... Args>
  static JSObject *
  CustomCreate(JSContext *cx, WrappedType *coreObject, Args &&...args) noexcept
  {
    JS::Rooted<JSObject *> jsObject{cx, Create(cx, Reference{coreObject})};
    Derived::Finalize(cx, jsObject, coreObject, std::forward<Args>(args)...);
    return jsObject;
  }

  static JSObject *
  Create(JSContext *cx, const Reference &object) noexcept
  {
    // we take and hold a reference to this object, keeping it alive
    auto tmp = Reference{object};
    return Create(cx, std::move(tmp));
  }

  static JSObject *
  Create(JSContext *cx, Reference &&object) noexcept
  {
    JS::Rooted<JSObject *> obj(cx, JS_NewObject(cx, &clasp));
    if (!obj) {
      return nullptr;
    }

    WrappedType *ptr = object.Get();
    JS_SetReservedSlot(obj, Derived::ThisPointer, JS::PrivateValue(std::move(object).DisOwn().Forget()));

    // Types with additional (more complex) setup/config opts into that, by exposing the static function Configure
    if constexpr (requires(Derived d, JSContext *cx, JSObject *obj, WrappedType *t) {
                    Derived::Configure(cx, obj, t);
                  }) {
      Derived::Configure(cx, obj, ptr);
    }

    // Types with properties exposes a static JSPropertySpec[] and it gets defined here
    if constexpr (requires { Derived::PropertiesSpec; }) {
      JS_DefineProperties(cx, obj, Derived::PropertiesSpec);
    }

    // Types with methods exposes a static JSFunctionSpec[] and it gets defined here
    if constexpr (requires(Derived d, JSContext *cx, JSObject *obj) { Derived::FunctionSpec; }) {
      JS_DefineFunctions(cx, obj, Derived::FunctionSpec);
    }

    return obj;
  }

  static Derived *
  GetThis(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
  {
    JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
    return Get(args.thisv().toObject());
  }

  // Hand out a new reference to the debugger core object
  constexpr Reference
  Get() noexcept
  {
    JSObject *thisJs = Self::AsObject(static_cast<Derived *>(this));
    Untraced<WrappedType> pObj{JS::GetMaybePtrFromReservedSlot<WrappedType>(thisJs, Derived::ThisPointer)};
    return pObj.CloneReference();
  }

  // Hand out a new reference to the debugger core object
  static constexpr Reference
  Get(JSObject *This) noexcept
  {
    Untraced<WrappedType> pObj{JS::GetMaybePtrFromReservedSlot<WrappedType>(This, Derived::ThisPointer)};
    return pObj.CloneReference();
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

// Implement a Javascript type for `WrappedType`. The pointed to core object is a raw pointer type, unlike
// `RefPtrJsObject` which works on `Ref<T>` instead of `T*`. For some types this is safe; like TraceeController,
// which is a type for objects, when created will never be destroyed.
template <typename Derived, typename WrappedType, StringLiteral string> struct PtrJsObject
{
  // Unfortunately we can't pass WrappedType via Derived. Oh my lord meta programming and compile time programming
  // in C++ is trash, 40 years later.
  using Self = RefPtrJsObject<Derived, WrappedType, string>;
  using Reference = WrappedType *;

  static constexpr const char *Name = string.CString();

  // When a CustomObject is traced, it must trace the stored box.
  static constexpr void
  TraceSubobjects(JSTracer *trc, JSObject *obj) noexcept
    requires(HasTraceFunction<Derived>)
  {
    FromObject(obj)->trace(trc);
  }

  static constexpr bool
  ResolveProperty(JSContext *cx, JS::HandleObject obj, JS::HandleId id, bool *resolved) noexcept
  {
    JS::Rooted<JSObject *> object{cx, obj};
    return FromObject(object)->resolve(cx, id, resolved);
  }

  static consteval JSClassOps
  ClassOps() noexcept
  {
    // This type will never have a `finalize` method because it will never actually own the object.
    if constexpr (HasResolve<Derived>) {
      return JSClassOps{.resolve = &ResolveProperty, .finalize = nullptr, .trace = &TraceSubobjects};
    } else {
      return JSClassOps{.resolve = nullptr, .finalize = nullptr, .trace = &TraceSubobjects};
    }
  }

  static constexpr JSClassOps classOps = ClassOps();

  static constexpr JSClass clasp = {.name = Name,
                                    .flags =
                                      JSCLASS_HAS_RESERVED_SLOTS(Derived::SlotCount) | JSCLASS_FOREGROUND_FINALIZE,
                                    .cOps = &classOps};

  template <typename... Args>
  static JSObject *
  CustomCreate(JSContext *cx, Reference coreObject, Args &&...args) noexcept
  {
    JS::Rooted<JSObject *> jsObject{cx, Create(cx, coreObject)};
    Derived::Finalize(cx, jsObject, coreObject, std::forward<Args>(args)...);
    return jsObject;
  }

  static JSObject *
  Create(JSContext *cx, const Reference object) noexcept
  {
    JS::Rooted<JSObject *> obj(cx, JS_NewObject(cx, &clasp));
    if (!obj) {
      return nullptr;
    }

    JS_SetReservedSlot(obj, Derived::ThisPointer, JS::PrivateValue(object));

    // Types with properties exposes a static JSPropertySpec[] and it gets defined here
    if constexpr (requires { Derived::PropertiesSpec; }) {
      JS_DefineProperties(cx, obj, Derived::PropertiesSpec);
    }

    // Types with methods exposes a static JSFunctionSpec[] and it gets defined here
    if constexpr (requires(Derived d, JSContext *cx, JSObject *obj) { Derived::FunctionSpec; }) {
      JS_DefineFunctions(cx, obj, Derived::FunctionSpec);
    }

    return obj;
  }

  // Hand out a new reference to the debugger core object
  constexpr Reference
  Get() noexcept
  {
    JSObject *thisJs = Self::AsObject(static_cast<Derived *>(this));
    return Get(thisJs);
  }

  // Hand out a new reference to the debugger core object
  static constexpr Reference
  Get(JSObject *This) noexcept
  {
    return JS::GetMaybePtrFromReservedSlot<WrappedType>(This, Derived::ThisPointer);
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