/** LICENSE TEMPLATE */
#pragma once
#include <concepts>
#include <expected>
#include <quickjs/quickjs.h>
#include <span>
#include <utils/scope_defer.h>
#include <utils/smartptr.h>

#define GetThisOrReturnException(variable, msg)                                                                   \
  GetNative(context, thisValue);                                                                                  \
  if (!variable) {                                                                                                \
    return JS_ThrowTypeError(context, msg);                                                                       \
  }

#define FOR_EACH_TYPE(EACH_TYPE)                                                                                  \
  EACH_TYPE(Variable)                                                                                             \
  EACH_TYPE(Frame)                                                                                                \
  EACH_TYPE(Breakpoint)                                                                                           \
  EACH_TYPE(BreakpointStatus)                                                                                     \
  EACH_TYPE(Supervisor)                                                                                           \
  EACH_TYPE(TaskInfo)

enum class JavascriptClasses : JSClassID
{
  // The actual init start as of the version used for mdb is 56.
  START = 70,
  FOR_EACH_TYPE(DEFAULT_ENUM)
};

PREDEFINED_ENUM_TYPE_METADATA(JavascriptClasses, FOR_EACH_TYPE, DEFAULT_ENUM)

namespace mdb {

struct JSBindingLeakHelper
{
  static constexpr mdb::RefPtrLeakAccessKey
  Key() noexcept
  {
    return {};
  }
};

namespace js {
// Helper to concatenate arrays at compile time
template <typename T, std::size_t N, std::size_t M, std::size_t... I1, std::size_t... I2>
constexpr std::array<T, N + M>
ConcatenateImplementation(
  const std::array<T, N> &a1, const std::array<T, M> &a2, std::index_sequence<I1...>, std::index_sequence<I2...>)
{
  return { a1[I1]..., a2[I2]... };
}

template <typename T, std::size_t N, std::size_t M>
constexpr std::array<T, N + M>
ArrayConcat(const std::array<T, N> &a1, const std::array<T, M> &a2)
{
  return ConcatenateImplementation(a1, a2, std::make_index_sequence<N>{}, std::make_index_sequence<M>{});
}

template <typename T>
concept HasFinalizer = requires(JSRuntime *runTime, JSValue value) { T::Finalizer(runTime, value); };

template <typename T>
concept HasFactory = requires(JSRuntime *runTime, JSValue value) { T::Factory(runTime, value); };

template <typename T>
concept Bindable = requires(T t) {
  { T::PrototypeFunctions() } -> std::convertible_to<std::span<JSCFunctionListEntry>>;
  { T::JavascriptName() } -> std::convertible_to<const char *>;
};

#define ClassArgs() (JSContext * context, JSValueConst thisValue, int argCount, JSValueConst *argv)->JSValue

#define ClassMethodSig(name, ...)                                                                                 \
  static auto name(JSContext *context, JSValueConst thisValue, int argCount, JSValueConst *argv) -> JSValue;

#define ClassMethodImpl(type, name) auto type::name ClassArgs()

#define ClassMethodTodo(Method)                                                                                   \
  {                                                                                                               \
    return JS_ThrowTypeError(context, #Method " method not implemented");                                         \
  }

#define ClassMethodImplTodo(type, method) ClassMethodImpl(type, method) ClassMethodTodo(method)

#define DefaultInterface(Name)                                                                                    \
  static std::span<const JSCFunctionListEntry> PrototypeFunctions() noexcept;                                     \
                                                                                                                  \
  constexpr static const char *JavascriptName() { return #Name; }

#define ClassMethod

consteval auto
FunctionEntry(const char *name, u8 argCount, auto fn) -> JSCFunctionListEntry
{
  return { name, (1 << 1) | (1 << 0), 0, 0, { .func = { argCount, JS_CFUNC_generic, { .generic = fn } } } };
}

constexpr auto
ToStringTag(const char *name) -> JSCFunctionListEntry
{
  return { "[Symbol.toStringTag]", (1 << 0), 3, 0, { .str = name } };
}

constexpr auto
ToStringTag(std::string_view name) -> JSCFunctionListEntry
{
  return { "[Symbol.toStringTag]", (1 << 0), 3, 0, { .str = name.data() } };
}

enum class PropertyReadError : u8
{
  ValueNotAnObject,
  ValueUndefined,
  NoPropertyWithThatName
};

template <class T, class U> inline constexpr bool Is = std::is_same_v<T, U>;

template <typename T>
std::expected<T, PropertyReadError>
GetProperty(JSContext *context, JSValueConst obj, const char *propertyName)
{

  if (JS_IsUndefined(obj)) {
    return std::unexpected(PropertyReadError::ValueNotAnObject);
  }

  JSValue value = JS_GetPropertyStr(context, obj, propertyName);
  ScopedDefer defer{ [&]() { JS_FreeValue(context, value); } };

  if (JS_IsUndefined(value)) {
    return std::unexpected(PropertyReadError::ValueUndefined);
  }

  T result;
  if constexpr (Is<T, double>) {
    JS_ToFloat64(context, &result, value);
  } else if constexpr (Is<T, int>) {
    JS_ToInt32(context, &result, value);
  } else if constexpr (Is<T, std::string>) {
    auto str = JS_ToCString(context, value);
    result = str ? str : "";
    JS_FreeCString(context, str);
  } else if constexpr (Is<T, u32>) {
    JS_ToUint32(context, &result, value);
  } else if constexpr (Is<T, i64>) {
    JS_ToInt64(context, &result, value);
  } else if constexpr (Is<T, bool>) {
    result = JS_ToBool(context, value);
  } else {
    static_assert(always_false<T>, "Unsupported property type");
  }

  return result;
}

template <typename T, typename NativeType>
concept HasExoticMethods = requires(JSContext *context, NativeType *nativeType) {
  { T::ExoticMethods() } -> std::same_as<JSClassExoticMethods>; // member variable 'value' of type int
  { T::CacheLayout(context, nativeType) };
};

template <typename BindingType, typename NativeType, JavascriptClasses ClassId> struct JSBinding
{
  static_assert(ClassId > static_cast<JavascriptClasses>(56));
#ifdef MDB_DEBUG
  static bool sClassInitialized;
#endif

  JSContext *mContext;
  JSValue mValue;

  void
  Reset() noexcept
  {
    if (!JS_IsUndefined(mValue)) {
      // Javascript types never get to manage memory manually.
      // For now, only RefPtr is allowed as any form of memory management, and so, memory management is delegated
      // to it. But in the future, I'll also add std::shared_ptr. Javascript objects that use a T*
      // and that also can get created in native code (for instance, createa JSBinding object on the stack because
      // it needs to passed in as a function argument to js code) will have it's native pointer set to nullptr,
      // when ~JSBinding runs, that way js can safely hold on to the JSValue, but it will not have access to the
      // native data no more. This way we protect ourselves from JS trying to reach memory it can't/shouldn't reach
      if constexpr (!IsRefCountable<NativeType>) {
        JS_SetOpaque(mValue, nullptr);
      }
      JS_FreeValue(mContext, mValue);
    }
  }

public:
  constexpr ~JSBinding() noexcept { Reset(); }

  JSValue &
  GetValue(this auto &&self) noexcept
  {
    return self.mValue;
  }

  consteval static auto
  GetClassId() noexcept
  {
    return std::to_underlying(ClassId);
  }

  constexpr static auto
  JavascriptName() noexcept -> std::string_view
  {
    return Enum<JavascriptClasses>::ToString(ClassId);
  }

  static void
  SetExoticMethods(JSClassDef &def)
    requires(HasExoticMethods<BindingType, NativeType>)
  {
    def.exotic = &BindingType::ExoticMethods();
  }

  static void
  Register(JSContext *context)
  {
    static_assert(Bindable<BindingType>, "BindingType must satisfy Bindable concept");
    if (sClassInitialized) {
      std::terminate();
    }

    JSClassDef definition;

    definition.class_name = JavascriptName().data();

    SetExoticMethods(definition);

    if constexpr (HasFinalizer<BindingType>) {
      definition.finalizer = BindingType::Finalizer;
    } else {
      definition.finalizer = nullptr;
    }

    JS_NewClass(JS_GetRuntime(context), GetClassId(), &definition);

    JSValue prototype = JS_NewObject(context);

    JS_SetPropertyFunctionList(
      context, prototype, BindingType::PrototypeFunctions().data(), BindingType::PrototypeFunctions().size());

    JS_SetClassProto(context, GetClassId(), prototype);

    if constexpr (HasFactory<BindingType>) {
      JSValue globalObject = JS_GetGlobalObject(context);
      JS_SetPropertyStr(context,
        globalObject,
        BindingType::FactoryName(),
        JS_NewCFunction(
          context, BindingType::Factory(), BindingType::FactoryName(), BindingType::FactoryArgumentsCount()));
      JS_FreeValue(context, globalObject);
    }
    sClassInitialized = true;
  }

  static NativeType *
  GetNative(JSContext *context, JSValueConst object) noexcept
  {
    auto *pointer = JS_GetOpaque2(context, object, GetClassId());
    return pointer ? static_cast<NativeType *>(pointer) : nullptr;
  }

  // The created object which is used in the javascript code
  static JSValue
  CreateValue(JSContext *context, NativeType *value) noexcept
  {
    if constexpr (HasExoticMethods<BindingType, NativeType>) {
      BindingType::CacheLayout(context, value);
    }

    JSValue object = JS_NewObjectClass(context, GetClassId());
    if (JS_IsException(object)) {
      return object;
    }
    JS_SetOpaque(object, static_cast<void *>(value));
    return object;
  }

  static JSValue
  CreateValue(JSContext *context, RefPtr<NativeType> value)
    requires(IsRefCountable<NativeType>)
  {
    if constexpr (HasExoticMethods<BindingType, NativeType>) {
      BindingType::CacheLayout(context, value);
    }

    JSValue object = JS_NewObjectClass(context, GetClassId());
    if (JS_IsException(object)) {
      return object;
    }
    // We've taken a RefPtr, and we leak it, so now a Javascript object holds that reference instead.

    LeakedRef<NativeType> res = value.Leak(JSBindingLeakHelper::Key());
    JS_SetOpaque(object, static_cast<void *>(res.Forget()));
    return object;
  }

  /** Creates an object of type `BindingType` to live on the stack. When that object's destructor is ran,
   * the native data associated with that JSValue, will be set to nullptr, so that the JS engine can't access it.
   * This is a poor mans version of a "stack rooted" native value. */
  static BindingType
  CreateStackBoundValue(JSContext *context, NativeType *value)
  {
    return BindingType{ JSBinding{ .mContext = context, .mValue = CreateValue(context, value) } };
  }

  static void
  Finalize(JSRuntime *rt, JSValue val)
  {
    void *ptr = JS_GetOpaque(val, std::to_underlying(ClassId));
    if (!ptr) {
      return;
    }

    if constexpr (IsRefCountable<NativeType>) {
      static_cast<LeakedRef<NativeType> *>(ptr)->Drop();
    }
  }
};
} // namespace js
} // namespace mdb
