/** LICENSE TEMPLATE */
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
#include "js/TracingAPI.h"
#include "js/TypeDecls.h"
#include "js/Warnings.h"
#include "jsfriendapi.h"
#include "mdbjs/event_dispatcher.h"
#include "mdbjs/supervisorjs.h"
#include "mdbjs/taskinfojs.h"
#include "mdbjs/util.h"
#include "supervisor.h"
#include <jsapi.h>
#include <tracer.h>
#include <utils/logger.h>

namespace mdb::js {

void
AppScriptingInstance::AddTrace(RegisterTraceFunction &&fn) noexcept
{
  mMdbObject.AddTrace(std::move(fn));
}

EventDispatcher *
AppScriptingInstance::GetEventDispatcher() noexcept
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
RuntimeGlobal::GetTask(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
  if (!args[0].isInt32()) {
    JS_ReportErrorASCII(cx, "Argument to get_task must be an int32.");
    return false;
  }
  auto taskInfo = Tracer::Get().GetTask(args[0].toInt32());
  if (!taskInfo) {
    args.rval().setNull();
    return true;
  }
  JS::Rooted<JSObject *> task(cx, JSTaskInfo::Create(cx, taskInfo));
  args.rval().setObject(*task);
  return true;
}

bool
RuntimeGlobal::PrintThreads(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);

  std::string buffer;
  buffer.reserve(4096);
  // Define your custom string representation

  auto iterator = std::back_inserter(buffer);
  for (auto supervisor : Tracer::Get().GetAllProcesses()) {
    iterator = ToString(iterator, supervisor);
    *iterator++ = '\n';

    for (const auto &t : supervisor->GetThreads()) {
      iterator = ToString(iterator, *t.mTask);
      *iterator++ = '\n';
    }
    iterator = fmt::format_to(iterator, "----------\n");
  }

  JS::Rooted<JSString *> str{cx, JS_NewStringCopyN(cx, buffer.data(), buffer.size())};
  args.rval().setString(str);
  return true;
}

bool
RuntimeGlobal::PrintProcesses(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);

  std::string buffer;
  buffer.reserve(4096);
  // Define your custom string representation

  auto iterator = std::back_inserter(buffer);
  for (auto supervisor : Tracer::Get().GetAllProcesses()) {
    iterator = ToString(iterator, supervisor);
    *iterator++ = '\n';
  }

  JSString *str = JS_NewStringCopyN(cx, buffer.data(), buffer.size());
  args.rval().setString(str);
  return true;
}

static consteval auto
GlobalFunctionsInfo() noexcept
{
#ifdef FN
#undef FN
#endif
#define FN(FUNC, NAME, ARGS, FLAGS, INFO, USAGE) std::tuple{NAME, std::size(ARGS), INFO##sv},
  return std::to_array({FOR_EACH_GLOBAL_FN(FN)});
#undef FN
}

bool
RuntimeGlobal::Help(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
  auto globalFns = GlobalFunctionsInfo();
  std::string buffer;
  buffer.reserve(4096);
  auto it = std::back_inserter(buffer);
  it = fmt::format_to(it, "Global functions\n");
  for (const auto &[name, argCount, helpInfo] : globalFns) {
    it = fmt::format_to(it, "{}, arg count: {} - {}\n", name, argCount, helpInfo);
  }

  JSString *str = JS_NewStringCopyN(cx, buffer.data(), buffer.size());
  args.rval().setString(str);
  return true;
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
  PANIC("Finalizing MdbObject is a bug");
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
MdbObject::CreateAndBindToJsObject(AppScriptingInstance *runtime, MdbObject *handle) noexcept
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
AppScriptingInstance::DefineDebuggerObject(JS::HandleObject global) noexcept
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
AppScriptingInstance::InitRuntime() noexcept
{
  JSAutoRealm ar(mContext, mGlobalObject);

  JS::RootedObject global{mContext, mGlobalObject};
  if (!DefineDebuggerObject(global)) {
    PANIC("Failed to create mdb object");
  }

  mEventDispatcher = EventDispatcher::Create(this);
}

/* static */
AppScriptingInstance *
AppScriptingInstance::Create(JSContext *context, JSObject *globalObject) noexcept
{
  return new AppScriptingInstance{context, globalObject};
}

JSContext *
AppScriptingInstance::GetRuntimeContext() noexcept
{
  return mContext;
}

JSObject *
AppScriptingInstance::GetRuntimeGlobal() noexcept
{
  return mGlobalObject;
}

Expected<JSFunction *, std::string>
AppScriptingInstance::SourceBreakpointCondition(u32 breakpointId, std::string_view condition) noexcept
{
  JSAutoRealm ar(mContext, GetRuntimeGlobal());
  ASSERT(::js::GetContextRealm(mContext), "Context realm retrieval failed.");
  JS::EnvironmentChain envChain{mContext, JS::SupportUnscopables::Yes};
  if (envChain.length() != 0) {
    ASSERT(::js::IsObjectInContextCompartment(envChain.chain()[0], mContext),
           "Object is not in context compartment.");
  }

  // Do the junk Gecko is supposed to do before calling into JSAPI.
  for (size_t i = 0; i < envChain.length(); ++i) {
    JS::ExposeObjectToActiveJS(envChain.chain()[i]);
  }
  constexpr auto argNames = std::to_array({"tc", "task", "bp"});
  auto file = fmt::format("breakpoint:{}", breakpointId);
  auto fnName = fmt::format("bpCondition_{}", breakpointId);
  auto src = SourceFromString(mContext, condition);
  ASSERT(src.is_expected(), "expected source to have been constructed");
  DBGLOG(core, "source constructed: {} bytes", src.value().length());
  JS::RootedObject global(mContext, mGlobalObject);
  JS::CompileOptions options{mContext};

  options.setFileAndLine("inline", breakpointId);

  JS::Rooted<JSFunction *> func{mContext, JS::CompileFunction(mContext, envChain, options, fnName.c_str(),
                                                              argNames.size(), argNames.data(), src.value())};
  if (!func) {
    DBGLOG(core, "failed to compile event handler: {}", condition);
    return ConsumePendingException(mContext)
      .transform([](auto &&str) -> mdb::Unexpected<std::string> { return mdb::unexpected(std::move(str)); })
      .value_or(mdb::Unexpected{std::string{"Failed"}});
  }
  return expected<JSFunction *>(func.get());
}

template <typename StdString>
static bool
FormatResult(JSContext *cx, JS::HandleValue value, StdString &writeBuffer)
{
  JS::RootedString str(cx);

  /* Special case format for strings */
  if (value.isString()) {
    str = value.toString();
    return ToStdString(cx, str, writeBuffer);
  }

  str = JS::ToString(cx, value);

  if (!str) {
    JS_ClearPendingException(cx);
    str = JS_ValueToSource(cx, value);
  }

  if (!str) {
    JS_ClearPendingException(cx);
    if (value.isObject()) {
      const JSClass *klass = JS::GetClass(&value.toObject());
      if (klass) {
        str = JS_NewStringCopyZ(cx, klass->name);
      } else {
        writeBuffer.append("[unknown object]");
        return true;
      }
    } else {
      writeBuffer.append("[unknown non-object]");
      return true;
    }
  }

  if (!str) {
    JS_ClearPendingException(cx);
    writeBuffer.append("[invalid class]");
    return true;
  }

  if (!ToStdString(cx, str, writeBuffer)) {
    JS_ClearPendingException(cx);
    writeBuffer.clear();
    writeBuffer.append("[invalid string]");
    return false;
  }

  return true;
}

std::pmr::string *
AppScriptingInstance::ReplEvaluate(std::string_view input, Allocator *allocator) noexcept
{
  static int ReplLineNumber = 1;
  std::pmr::string *res = allocator->new_object<std::pmr::string>();
  JS::CompileOptions options(mContext);
  options.setFileAndLine("repl", ReplLineNumber++);

  auto src = SourceFromString(mContext, input);

  if (src.is_error()) {
    auto &e = src.error();
    std::copy(e.begin(), e.end(), std::back_inserter(*res));
    return res;
  }

  JS::RootedValue result(mContext);
  if (!JS::Evaluate(mContext, options, src.value(), &result)) {
    auto exception = ConsumePendingException(mContext);
    if (exception) {
      fmt::format_to(std::back_inserter(*res), "{}", exception.value());
    } else {
      fmt::format_to(std::back_inserter(*res), "Failed to evaluate {}", input);
    }
    return res;
  }

  if (result.isUndefined()) {
    return res;
  }

  if (!FormatResult(mContext, result, *res)) {
    DBGLOG(interpreter, "repl evaluation unsuccesful for '{}'", input);
  }
  return res;
}

std::string
AppScriptingInstance::ReplEvaluate(std::string_view input) noexcept
{
  static int ReplLineNumber = 1;
  JS::CompileOptions options(mContext);
  options.setFileAndLine("repl", ReplLineNumber);

  auto src = SourceFromString(mContext, input);

  if (src.is_error()) {
    return src.error();
  }

  JS::RootedValue result(mContext);
  if (!JS::Evaluate(mContext, options, src.value(), &result)) {
    return fmt::format("Failed to evaluate: {}", input);
  }

  JS_MaybeGC(mContext);

  if (result.isUndefined()) {
    return "";
  }
  std::string res{};
  if (!FormatResult(mContext, result, res)) {
    DBGLOG(interpreter, "repl evaluation unsuccesful for '{}'", input);
  }
  return res;
}

mdb::Expected<void, std::string>
AppScriptingInstance::EvaluateJavascriptStringView(std::string_view javascriptSource) noexcept
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
AppScriptingInstance::EvaluateJavascriptFileView(std::string_view filePath) noexcept
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
AppScriptingInstance::EvaluateJavascriptString(const std::string &javascriptSource) noexcept
{
  return EvaluateJavascriptStringView(javascriptSource);
}

mdb::Expected<void, std::string>
AppScriptingInstance::EvaluateJavascriptFile(const std::string &filePath) noexcept
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

bool
ConsumePendingException(JSContext *ctx, std::pmr::string &writeToBuffer) noexcept
{
  if (JS_IsExceptionPending(ctx)) {
    JS::RootedValue exception(ctx);
    if (JS_GetPendingException(ctx, &exception)) {
      JS_ClearPendingException(ctx);

      JS::RootedString exceptionString(ctx, JS::ToString(ctx, exception));
      return ToStdString(ctx, exceptionString, writeToBuffer);
    }
    return false;
  } else {
    return false;
  }
}
} // namespace mdb::js