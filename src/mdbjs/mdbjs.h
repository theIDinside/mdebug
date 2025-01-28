#pragma once
#include "js/Class.h"
#include "js/PropertyDescriptor.h"
#include "js/PropertySpec.h"
#include "js/RootingAPI.h"
#include "js/TracingAPI.h"
#include "js/TypeDecls.h"
#include "mdbjs/event_dispatcher.h"
#include "utils/expected.h"
#include "utils/logger.h"
#include <optional>
#include <string>

class JSContext;
class Tracer;

extern const JSClassOps DefaultGlobalClassOps;

namespace mdb::js {

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

public:
  static JSObject *create(JSContext *cx) noexcept;
};

class ScriptRuntime;

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

  // When the CustomObject is collected, delete the stored box.
  static void finalize(JS::GCContext *gcx, JSObject *obj);

  // When a CustomObject is traced, it must trace the stored box.
  static void TraceSubsystems(JSTracer *trc, JSObject *obj);

  static constexpr JSClassOps classOps = {.finalize = finalize, .trace = TraceSubsystems};

  static constexpr JSClass clasp = {.name = "mdb",
                                    .flags = JSCLASS_HAS_RESERVED_SLOTS(SlotCount) | JSCLASS_FOREGROUND_FINALIZE,
                                    .cOps = &classOps};

  static JSObject *CreateAndBindToJsObject(ScriptRuntime *runtime, MdbObject *handle) noexcept;
  void AddTrace(RegisterTraceFunction &&fn) noexcept;
};

class ScriptRuntime
{
  friend RuntimeGlobal;
  EventDispatcher *mEventDispatcher;
  MdbObject mMdbObject{};

  // A RootedValue of this must live on the stack before init of `Interpreter` and must not go out of scope
  JSContext *mContext;
  JSObject *mGlobalObject;
  bool DefineDebuggerObject(JS::HandleObject global) noexcept;

  ScriptRuntime(JSContext *context, JSObject *globalObject) noexcept
      : mContext(context), mGlobalObject(globalObject)
  {
  }

  bool GuessIfSourceIsFunction(std::string_view source) noexcept;

public:
  static ScriptRuntime *Create(JSContext *context, JSObject *globalObject) noexcept;
  void InitRuntime() noexcept;

  EventDispatcher *GetEventDispatcher() noexcept;
  JSContext *GetRuntimeContext() noexcept;
  JSObject *GetRuntimeGlobal() noexcept;

  mdb::Expected<JSFunction *, std::string> SourceBreakpointCondition(u32 breakpointId,
                                                                     std::string_view condition) noexcept;
  mdb::Expected<void, std::string> EvaluateJavascriptStringView(std::string_view javascriptSource) noexcept;
  mdb::Expected<void, std::string> EvaluateJavascriptFileView(std::string_view filePath) noexcept;
  mdb::Expected<void, std::string> EvaluateJavascriptString(const std::string &javascriptSource) noexcept;
  mdb::Expected<void, std::string> EvaluateJavascriptFile(const std::string &filePath) noexcept;
};

// Todo: In the future this interface will probably change
// where we instead return some structured data for the exception that happened in js-land.
// For now, if this returns a non-none value, it means an exception happened (and we consumed it).
std::optional<std::string> ConsumePendingException(JSContext *context) noexcept;
} // namespace mdb::js

using MdbScriptRuntime = mdb::js::ScriptRuntime;