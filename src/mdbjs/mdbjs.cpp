#include "mdbjs.h"
#include "js/CallAndConstruct.h"
#include "js/CompilationAndEvaluation.h"
#include "js/CompileOptions.h"
#include "js/Conversions.h"
#include "js/EnvironmentChain.h"
#include "js/ErrorReport.h"
#include "js/Exception.h"
#include "js/Initialization.h"
#include "js/Object.h"
#include "js/PropertyAndElement.h"
#include "js/RootingAPI.h"
#include "js/TypeDecls.h"
#include "js/Warnings.h"
#include "mdbjs/event_dispatcher.h"
#include "mdbjs/util.h"
#include <jsapi.h>
#include <tracer.h>
#include <utils/logger.h>

namespace mdb::js {

EventDispatcher *
ScriptRuntime::GetEventDispatcher() noexcept
{
  return mEventDispatcher;
}

/* The class of the global object. */
const JSClass RuntimeGlobal::klass = {"RuntimeGlobal",
                                      JSCLASS_GLOBAL_FLAGS | JSCLASS_HAS_RESERVED_SLOTS(RuntimeGlobal::SlotCount),
                                      &JS::DefaultGlobalClassOps};

constexpr JSFunctionSpec RuntimeGlobal::sRuntimeFunctions[];

/* static */
RuntimeGlobal *
RuntimeGlobal::priv(JSObject *global) noexcept
{
  auto *retval = JS::GetMaybePtrFromReservedSlot<RuntimeGlobal>(global, GlobalSlot);
  VERIFY(retval, "Failed JS::GetMaybePtrFromReservedSlot");
  return retval;
}

bool
RuntimeGlobal::GetSupervisor(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  TODO("Implement RuntimeGlobal::GetSupervisor");
}

bool
RuntimeGlobal::Log(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);

  if (args.length() < 2 || ((!args[0].isNumber() && !args[0].isInt32()) || !args[1].isString())) {
    DBGLOG(interpreter, "mdb.log() called with the wrong parameters: {}", args.length());
    // TODO: set pending exception so that client code knows something went wrong.
    JS_ReportErrorASCII(cx, "log requires arguments (channel: int, message: string).");
    return false;
  } else {
    auto channelId = args[0].toInt32();
    auto parsedChannelId = Enum<Channel>::FromInt(channelId);
    if (!parsedChannelId) {
      JS_ReportErrorASCII(cx, "Unknown channel id %d", channelId);
      return false;
    }

    JS::RootedString exceptionString(cx, JS::ToString(cx, args[1]));
    if (exceptionString) {
      JS::UniqueChars exceptionCString = ::JS_EncodeStringToUTF8(cx, exceptionString);
      if (exceptionCString) {
        auto channel = logging::GetLogChannel(parsedChannelId.value());
        channel->Log(std::string_view{exceptionCString.get()});
      }
    }
  }
  args.rval().setNull();
  return true;
}

JSObject *
RuntimeGlobal::create(JSContext *cx) noexcept
{
  JS::RealmOptions options;
  JS::RootedObject global(
    cx, JS_NewGlobalObject(cx, &RuntimeGlobal::klass, nullptr, JS::FireOnNewGlobalHook, options));

  RuntimeGlobal *priv = new RuntimeGlobal();
  JS_SetReservedSlot(global, GlobalSlot, JS::PrivateValue(priv));

  // Define any extra global functions that we want in our environment.
  JSAutoRealm ar(cx, global);
  if (!JS_DefineFunctions(cx, global, RuntimeGlobal::sRuntimeFunctions)) {
    return nullptr;
  }

  if (!JS::InitRealmStandardClasses(cx)) {
    PANIC("JS::InitRealmStandardClasses failed");
  }

  return global;
}

/* static */
void
MdbObject::finalize(JS::GCContext *gcx, JSObject *obj)
{
  // delete MdbObject::fromObject(obj)->ownedBox();
  // Do NOT delete unownedBox().
}

void
MdbObject::TraceSubsystems(JSTracer *trc, JSObject *obj)
{
  MdbObject *object = reinterpret_cast<MdbObject *>(obj);
  for (auto &t : object->mSubSystemTracing) {
    t(trc);
  }
}

/* static */
JSObject *
MdbObject::CreateAndBindToJsObject(ScriptRuntime *runtime, MdbObject *handle) noexcept
{
  JSContext *cx = runtime->GetRuntimeContext();
  JS::Rooted<JSObject *> obj(cx, JS_NewObject(cx, &clasp));
  if (!obj) {
    PANIC("Failed to create mdb object");
  }

  JS_SetReservedSlot(obj, ThisPointer, JS::PrivateValue(handle));
  JS_SetReservedSlot(obj, ScriptRuntimePointer, JS::PrivateValue(runtime));
  if (!JS_DefineProperties(cx, obj, ReadOnlyPropertySpecs)) {
    PANIC("Failed to set read only properties");
  }

  return obj;
}

void
MdbObject::AddTrace(RegisterTraceFunction &&fn) noexcept
{
  DBGLOG(interpreter, "Adding subsystem to be traced.");
  mSubSystemTracing.emplace_back(std::move(fn));
}

// Define the "debugger" object and its "on" method
bool
ScriptRuntime::DefineDebuggerObject(JS::HandleObject global) noexcept
{
  // Create the "debugger" object

  JS::RootedObject debuggerObj(mContext, MdbObject::CreateAndBindToJsObject(this, &mMdbObject));
  if (!debuggerObj) {
    PANIC("Failed to create new (plain) object");
    return false;
  }

  // Add the "debugger" object to the global scope
  if (!JS_DefineProperty(mContext, global, "mdb", debuggerObj,
                         JSPROP_ENUMERATE | JSPROP_PERMANENT | JSPROP_READONLY)) {
    PANIC("Failed to add 'debugger' property on the global 'this' variable");
    return false;
  }

  return true;
}

void
ScriptRuntime::InitRuntime() noexcept
{
  JSAutoRealm ar(mContext, mGlobalObject);

  JS::RootedObject global{mContext, mGlobalObject};
  if (!DefineDebuggerObject(global)) {
    PANIC("Failed to create mdb object");
  }

  mEventDispatcher = EventDispatcher::Create(this);
}

/* static */
ScriptRuntime *
ScriptRuntime::Create(JSContext *context, JSObject *globalObject) noexcept
{
  return new ScriptRuntime{context, globalObject};
}

JSContext *
ScriptRuntime::GetRuntimeContext() noexcept
{
  return mContext;
}

JSObject *
ScriptRuntime::GetRuntimeGlobal() noexcept
{
  return mGlobalObject;
}

bool
ScriptRuntime::GuessIfSourceIsFunction(std::string_view source) noexcept
{
  return source.contains("return") || source.contains("=>") || source.contains("function");
}

mdb::Expected<JSFunction *, std::string>
ScriptRuntime::SourceBreakpointCondition(u32 breakpointId, std::string_view condition) noexcept
{
  if (GuessIfSourceIsFunction(condition)) {
    TODO_FMT("Implement ScriptRuntime::SourceBreakpointCondition {}", condition);
  } else {
    const auto processedSource = fmt::format("function (supervisor, taskId, breakpoint) {{ {} }}", condition);
    EXPECT(auto src, SourceFromString(mContext, processedSource));
    JS::RootedObject global(mContext, mGlobalObject);
    JS::CompileOptions options{mContext};
    JS::EnvironmentChain envChain{mContext, JS::SupportUnscopables::Yes};
    auto file = fmt::format("breakpoint:{}", breakpointId);
    auto fnName = fmt::format("bpCondition_{}", breakpointId);
    options.setIntroductionType("eventHandler").setFileAndLine(file.c_str(), 0).setDeferDebugMetadata();
    constexpr auto argNames = std::to_array({"pid", "tid", "bpId"});
    JS::Rooted<JSFunction *> func{mContext, JS::CompileFunction(mContext, envChain, options, fnName.c_str(),
                                                                argNames.size(), argNames.data(), src)};
    if (!func) {
      DBGLOG(core, "failed to compile event handler: {}", condition);
      return ConsumePendingException(mContext)
        .transform([](auto &&str) -> mdb::Unexpected<std::string> { return mdb::unexpected(std::move(str)); })
        .value_or(mdb::Unexpected{std::string{"Failed"}});
    }
    return mdb::expected<JSFunction *>(func.get());
  }
}

mdb::Expected<void, std::string>
ScriptRuntime::EvaluateJavascriptStringView(std::string_view javascriptSource) noexcept
{
  auto ctx = GetRuntimeContext();
  JS::RootedValue result(ctx);
  JS::CompileOptions options(ctx);
  options.setFileAndLine("inline", 1); // Set file name and line number for debugging purposes

  auto src = SourceFromString(ctx, javascriptSource);

  EXPECT_REF(auto &source, src);

  if (!JS::Evaluate(ctx, options, source, &result)) {
    if (auto exMessage = mdb::js::ConsumePendingException(ctx); exMessage) {
      return mdb::unexpected(fmt::format("Exception during script evaluation: {}", exMessage.value()));
    }
  }

  DBGLOG(interpreter, "Successfully sourced javascript");

  return {};
}

mdb::Expected<void, std::string>
ScriptRuntime::EvaluateJavascriptFileView(std::string_view filePath) noexcept
{
  ScopedFd f = ScopedFd::OpenFileReadOnly(filePath);
  auto sz = f.FileSize();
  std::string mFileContents;
  mFileContents.resize(sz);

  auto leftOfRead = sz;
  while (leftOfRead > 0) {
    auto res = read(f, mFileContents.data() + (sz - leftOfRead), leftOfRead);
    if (res == -1) {
      return mdb::unexpected<std::string>(
        fmt::format("failed to read source code file {}. Error: {}", filePath, strerror(errno)));
    }
    leftOfRead -= res;
  }

  return EvaluateJavascriptString(mFileContents);
}

mdb::Expected<void, std::string>
ScriptRuntime::EvaluateJavascriptString(const std::string &javascriptSource) noexcept
{
  return EvaluateJavascriptStringView(javascriptSource);
}

mdb::Expected<void, std::string>
ScriptRuntime::EvaluateJavascriptFile(const std::string &filePath) noexcept
{
  return EvaluateJavascriptFileView(filePath);
}

std::optional<std::string>
ConsumePendingException(JSContext *cx) noexcept
{
  if (JS_IsExceptionPending(cx)) {
    JS::RootedValue exception(cx);
    if (JS_GetPendingException(cx, &exception)) {
      JS_ClearPendingException(cx);

      JS::RootedString exceptionString(cx, JS::ToString(cx, exception));
      if (exceptionString) {
        JS::UniqueChars exceptionCString = ::JS_EncodeStringToUTF8(cx, exceptionString);
        if (exceptionCString) {
          return fmt::format("{}", exceptionCString.get());
        }
      }
    }
    return "JavaScript Exception: <failed to get pending exception>";
  } else {
    return std::nullopt;
  }
}
} // namespace mdb::js