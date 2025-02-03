/** LICENSE TEMPLATE */
#pragma once
#include "js/CharacterEncoding.h"
#include "js/Class.h"
#include "js/PropertyDescriptor.h"
#include "js/PropertySpec.h"
#include "js/RootingAPI.h"
#include "js/String.h"
#include "js/TracingAPI.h"
#include "js/TypeDecls.h"
#include "js/Value.h"
#include "mdbjs/event_dispatcher.h"
#include "mdbjs/util.h"
#include "utils/expected.h"
#include "utils/logger.h"
#include <limits>
#include <memory_resource>
#include <optional>
#include <string>

class JSContext;
class Tracer;

extern const JSClassOps DefaultGlobalClassOps;

namespace mdb::js {

// Todo: In the future this interface will probably change
// where we instead return some structured data for the exception that happened in js-land.
// For now, if this returns a non-none value, it means an exception happened (and we consumed it).
std::optional<std::string> ConsumePendingException(JSContext *context) noexcept;

class EventDispatcher;

class RuntimeGlobal
{
  enum Slots
  {
    GlobalSlot,
    SlotCount
  };

  RuntimeGlobal() noexcept = default;

  static RuntimeGlobal *priv(JSObject *global) noexcept;
  static const JSClass klass;

#define FOR_EACH_FN(FN)                                                                                           \
  FN(Log, "log", 2, 0)                                                                                            \
  FN(GetSupervisor, "supervisor", 1, 0)

#define DEFINE_FN(FUNC, ...) static bool FUNC(JSContext *cx, unsigned argc, JS::Value *vp) noexcept;
  FOR_EACH_FN(DEFINE_FN);

#define FN(FUNC, NAME, ARGS, FLAGS) JS_FN(NAME, &RuntimeGlobal::FUNC, ARGS, FLAGS),

  static constexpr JSFunctionSpec sRuntimeFunctions[] = {FOR_EACH_FN(FN) JS_FS_END};

#undef FOR_EACH_FN
#undef DEFINE_FN
#undef FN

public:
  static JSObject *create(JSContext *cx) noexcept;
};

class AppScriptingInstance;

using RegisterTraceFunction = std::function<void(JSTracer *trc)>;

// MDB Object. Assigned to the global object, so it will have at the minimum 1 reference count
// until the end of the application.
// Responsible for memory management, the public mdb API (functions found on mdb.foo(), mdb.bar())
// as well as where the subsystems can be reached from.

// You want to add a listener for some event, e.g. clone? it's mdb.events.on(mdb.events.clone, (pid, tid) => { ...
// })
class MdbObject
{
  std::vector<RegisterTraceFunction> mSubSystemTracing;

public:
  enum Slots
  {
    ThisPointer,
    ScriptRuntimePointer,
    SlotCount
  };

#define CHANNEL_ITEM(VARIANT, ...)                                                                                \
  JS_INT32_PS(#VARIANT, static_cast<int>(Channel::VARIANT), JSPROP_ENUMERATE | JSPROP_PERMANENT | JSPROP_READONLY),

#define EVENT_ITEM(VARIANT, ...)                                                                                  \
  JS_INT32_PS(#VARIANT, static_cast<int>(EventResult::VARIANT),                                                   \
              JSPROP_ENUMERATE | JSPROP_PERMANENT | JSPROP_READONLY),

  static constexpr JSPropertySpec ReadOnlyPropertySpecs[]{FOR_EACH_LOG(CHANNEL_ITEM)
                                                            FOR_EACH_EVENT_RESULT(EVENT_ITEM) JS_PS_END};
#undef CHANNEL_ITEM
#undef EVENT_ITEM

  // When the MdbObject is collected, delete the stored box.
  static void finalize(JS::GCContext *gcx, JSObject *obj);

  // When a MdbObject is traced, it must trace the stored box.
  static void TraceSubsystems(JSTracer *trc, JSObject *obj);

  static constexpr JSClassOps classOps = {.finalize = finalize, .trace = TraceSubsystems};

  static constexpr JSClass clasp = {.name = "mdb",
                                    .flags = JSCLASS_HAS_RESERVED_SLOTS(SlotCount) | JSCLASS_FOREGROUND_FINALIZE,
                                    .cOps = &classOps};

  static JSObject *CreateAndBindToJsObject(AppScriptingInstance *runtime, MdbObject *handle) noexcept;
  void AddTrace(RegisterTraceFunction &&fn) noexcept;
};

static consteval auto
ComputeEnumNames()
{
  u8 max = std::numeric_limits<u8>::max();
  JS::ValueType tMax = static_cast<JS::ValueType>(max);
  return tMax;
}

// `AppScriptingInstance` the interface between the debugger and the scripting mechanics/embedding of SpiderMonkey
// Responsible for sourcing javascsript code into objects and state that we can manipulate in a fashion that best
// suits us.
class AppScriptingInstance
{
  friend RuntimeGlobal;
  EventDispatcher *mEventDispatcher;
  MdbObject mMdbObject{};

  // A RootedValue of this must live on the stack before init of `Interpreter` and must not go out of scope
  JSContext *mContext;
  JSObject *mGlobalObject;
  bool DefineDebuggerObject(JS::HandleObject global) noexcept;

  AppScriptingInstance(JSContext *context, JSObject *globalObject) noexcept
      : mContext(context), mGlobalObject(globalObject)
  {
  }

public:
  static AppScriptingInstance *Create(JSContext *context, JSObject *globalObject) noexcept;
  void InitRuntime() noexcept;

  // Register tracing via Runtime, on the MdbObject, which has a persistent root to start tracing from
  void AddTrace(RegisterTraceFunction &&fn) noexcept;

  EventDispatcher *GetEventDispatcher() noexcept;
  JSContext *GetRuntimeContext() noexcept;
  JSObject *GetRuntimeGlobal() noexcept;

  template <typename ErrType> struct CallError
  {
    ErrType mError;
    std::string_view mErrorMessage;
  };

  /// Call function `compiledFunction` expecting template parameter `ExpectedReturnType` as return type.
  /// If `ExpectedReturnType` is int, but the return type from the javascript function is a boolean, we convert the
  /// boolean to an integer result (0 = false).
  /// std::string maps to JSString for now. No other string can therefore be used yet.
  template <typename ReturnType>
  std::optional<ReturnType>
  CallFunction(JS::Handle<JSFunction *> compiledFun, JS::HandleValueArray arguments,
               std::string &errorMessage) noexcept
  {
    JS::Rooted<JSFunction *> fn{mContext, compiledFun};
    JS::RootedValue rval(mContext);
    JS::Rooted<JSObject *> global(mContext, mGlobalObject);

    constexpr auto writeError = [](std::string &msg, std::string_view type) {
      fmt::format_to(std::back_inserter(msg), "Function had the wrong return type, expected: {}", type);
    };

    if (!JS_CallFunction(mContext, global, fn, arguments, &rval)) {
      auto exception = ConsumePendingException(mContext);
      fmt::format_to(std::back_inserter(errorMessage), "Failed to call function: {}",
                     exception.value_or("No exception found"));
      return {};
    }

    if constexpr (std::is_integral_v<ReturnType>) {
      bool isBool = rval.isBoolean();
      if (!rval.isInt32() && !isBool) {
        writeError(errorMessage, "int");
        return {};
      }
      // For the bozos who use < 0 for falsy.
      return !isBool ? rval.toInt32() : std::abs(static_cast<int>(rval.toBoolean()));
    } else if constexpr (std::is_same_v<ReturnType, std::string>) {
      if (!rval.isString()) {
        writeError(errorMessage, "string");
        return {};
      }
      JS::Rooted<JSString *> string{mContext, rval.toString()};
      std::string result;
      bool ok = ToStdString(mContext, string, result);
      if (!ok) {
        fmt::format_to(std::back_inserter(errorMessage), "Failed to copy string result");
        return {};
      }
      return std::make_optional<std::string>(std::move(result));
    } else if constexpr (std::is_same_v<ReturnType, JSObject>) {
      if (!rval.isObject()) {
        writeError(errorMessage, "object");
        return {};
      }
      return rval.toObjectOrNull();
    } else if constexpr (std::is_same_v<ReturnType, bool>) {
      if (!rval.isBoolean()) {
        writeError(errorMessage, "boolean");
        return {};
      }
      return rval.toBoolean();
    } else {
      static_assert(always_false<ReturnType>, "Unsupported type for this function");
    }
  }

  Expected<JSFunction *, std::string> SourceBreakpointCondition(u32 breakpointId,
                                                                std::string_view condition) noexcept;
  std::pmr::string ReplEvaluate(std::string_view input, std::pmr::memory_resource *allocator) noexcept;
  std::string ReplEvaluate(std::string_view input) noexcept;
  Expected<void, std::string> EvaluateJavascriptStringView(std::string_view javascriptSource) noexcept;
  Expected<void, std::string> EvaluateJavascriptFileView(std::string_view filePath) noexcept;
  Expected<void, std::string> EvaluateJavascriptString(const std::string &javascriptSource) noexcept;
  Expected<void, std::string> EvaluateJavascriptFile(const std::string &filePath) noexcept;
};
} // namespace mdb::js

using AppScriptingInstance = mdb::js::AppScriptingInstance;