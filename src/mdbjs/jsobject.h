#pragma once

#include "js/Class.h"
#include "js/GCTypeMacros.h"
#include "js/Object.h"
#include "js/TypeDecls.h"
#include "jsapi.h"
#include "utils/smartptr.h"
namespace mdb::js {

// Eventually we'll life this constraint IsRefPointer<T>, and instead specialize internally for cases where
// T is IsRefPointer and where it's not (and also rename the class).
template <typename T, StringLiteral string> struct RefPtrObject
{
  using Self = RefPtrObject<T, string>;
  static constexpr const char *Name = string.CString();
  enum Slots
  {
    CoreObjectPointer,
    SlotCount
  };

  // When a CustomObject is traced, it must trace the stored box.
  static constexpr void
  TraceSubobjects(JSTracer *trc, JSObject *obj)
  {
    if constexpr (requires(T t) { t.trace(trc); }) {
      fromObject(obj)->Get()->trace(trc);
    }
  }

  static consteval auto
  FinalizingOp(JS::GCContext *gcx, JSObject *thisJs)
  {
    using RefCountedType = typename T::Type;
    Untraced<RefCountedType> pObj =
      JS::GetMaybePtrFromReservedSlot<Untraced<RefCountedType>>(thisJs, CoreObjectPointer);
    pObj.Drop();
  }

  static constexpr JSClassOps classOps = {.finalize = FinalizingOp(), .trace = TraceSubobjects};

  static constexpr JSClass clasp = {
    .name = Name, .flags = JSCLASS_HAS_RESERVED_SLOTS(SlotCount) | JSCLASS_FOREGROUND_FINALIZE, .cOps = &classOps};

  static JSObject *
  Create(JSContext *cx, Ref<T> &&object) noexcept
    requires IsRefPointer<T>
  {
    JS::Rooted<JSObject *> obj(cx, JS_NewObject(cx, &clasp));
    if (!obj) {
      return nullptr;
    }
    JS_SetReservedSlot(obj, CoreObjectPointer, JS::PrivateValue(object.DisOwn()));

    return obj;
  }

  constexpr auto
  Get() noexcept
    requires(IsRefPointer<T>)
  {
    JSObject *thisJs = Self::asObject(this);
    using RefCountedType = typename T::Type;
    Untraced<RefCountedType> pObj =
      JS::GetMaybePtrFromReservedSlot<Untraced<RefCountedType>>(thisJs, CoreObjectPointer);
    return pObj.Take();
  }

  // Full type of JSObject is not known, so we can't inherit.
  static RefPtrObject *
  fromObject(JSObject *obj)
  {
    return reinterpret_cast<RefPtrObject *>(obj);
  }
  static JSObject *
  asObject(RefPtrObject *obj)
  {
    return reinterpret_cast<JSObject *>(obj);
  }
};
} // namespace mdb::js