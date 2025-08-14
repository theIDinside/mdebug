/** LICENSE TEMPLATE */
#include "mdbjs.h"
#include "lib/arena_allocator.h"

// mdb
#include <common.h>
#include <mdbjs/supervisorjs.h>
#include <mdbjs/taskinfojs.h>
#include <mdbjs/util.h>
#include <memory_resource>
#include <supervisor.h>
#include <tracer.h>
#include <utils/logger.h>

// system
// dependecy
#include <quickjs/quickjs.h>

namespace mdb::js {

Scripting *Scripting::sInstance = nullptr;

/* static */ JSValue
Scripting::GetSupervisor(JSContext *ctx, JSValueConst this_val, int argCount, JSValueConst *argv) noexcept
{
  return JS_UNDEFINED;
}

/* static */ JSValue
Scripting::Log(JSContext *ctx, JSValueConst this_val, int argCount, JSValueConst *argv) noexcept
{
  return JS_UNDEFINED;
}

/* static */ JSValue
Scripting::GetTask(JSContext *ctx, JSValueConst this_val, int argCount, JSValueConst *argv) noexcept
{
  Scripting *interp = (Scripting *)JS_GetContextOpaque(ctx);
  if (argCount < 0 || !JS_IsNumber(argv[0])) {
    return JS_ThrowTypeError(ctx, Scripting::HelpMessage("getThread").data());
  }

  i32 tid;
  if (!JS_ToInt32(ctx, &tid, argv[0])) {
    return JS_ThrowTypeError(ctx, "number conversion failed.");
  }

  auto taskInfo = Tracer::GetThreadByTidOrDebugId(tid);
  if (!taskInfo) {
    JS_UNDEFINED;
  }

  return JsTaskInfo::CreateValue(ctx, taskInfo);
}

/* static */ JSValue
Scripting::PrintThreads(JSContext *ctx, JSValueConst thisValue, int argCount, JSValueConst *argv) noexcept
{
  alloc::StackBufferResource<4096> alloc;
  std::pmr::string buffer{ &alloc };

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
    iterator = std::format_to(iterator, "----------\n");
  }

  auto v = JS_NewStringLen(ctx, buffer.data(), buffer.size());
  return v;
}

/* static */ JSValue
Scripting::PrintProcesses(JSContext *ctx, JSValueConst this_val, int argCount, JSValueConst *argv) noexcept
{
  return JS_UNDEFINED;
}

/* static */ JSValue
Scripting::Help(JSContext *ctx, JSValueConst this_val, int argCount, JSValueConst *argv) noexcept
{
  alloc::StackBufferResource<4096> rsrc;
  std::pmr::polymorphic_allocator alloc{ &rsrc };
  std::pmr::string &buffer = *alloc.new_object<std::pmr::string>();
  buffer.reserve(4096);
  auto it = std::back_inserter(buffer);
  it = std::format_to(it, "Global functions\n");
  for (const auto &[_, name, argCount, helpInfo] : FunctionDescriptors()) {
    it = std::format_to(it, "{}, arg count: {} - {}\n", name, argCount, helpInfo);
  }

  return JS_NewStringLen(ctx, buffer.data(), buffer.size());
}

void
Scripting::InitializeMdbModule() noexcept
{
  JSValue mdbObject = JS_NewObject(mContext);

  JSValue fn;

  for (const FunctionDescriptor &descriptor : FunctionDescriptors()) {
    fn = JS_NewCFunction(mContext, descriptor.mFn, descriptor.mName.data(), descriptor.mArgCount);
    JS_SetPropertyStr(mContext, mdbObject, descriptor.mName.data(), fn);
  }

  JSValue global_obj = JS_GetGlobalObject(mContext);
  JS_SetPropertyStr(mContext, global_obj, "mdb", mdbObject);
  JS_FreeValue(mContext, global_obj);
}

/* static */
Scripting *
Scripting::Create() noexcept
{
  VERIFY(sInstance == nullptr, "InterpreterInstance already created.");

  JSRuntime *runtime = JS_NewRuntime();
  JS_SetMemoryLimit(runtime, MegaBytes(128));
  JS_SetMaxStackSize(runtime, MegaBytes(2));

  JSContext *context = JS_NewContext(runtime);
  VERIFY(context, "Failed to create context");
  sInstance = new Scripting{ runtime, context };
  JS_SetContextOpaque(context, sInstance);
  sInstance->InitializeMdbModule();
  return sInstance;
}

/* static */
Scripting &
Scripting::Get() noexcept
{
  return *sInstance;
}

void
Scripting::Shutdown() noexcept
{
  JS_FreeContext(mContext);
  JS_FreeRuntime(mRuntime);
}

std::pmr::string *
Scripting::ReplEvaluate(Allocator *allocator, std::string_view input) noexcept
{
  static int ReplLineNumber = 1;
  std::pmr::string *res = allocator->new_object<std::pmr::string>();

  JSValue evalRes = JS_Eval(mContext, input.data(), input.size(), "<eval>", 0);

  auto jsString = JS_ToString(mContext, evalRes);
  auto string = JS_ToCString(mContext, jsString);

  ScopedDefer defer{ [&]() {
    JS_FreeValue(mContext, jsString);
    JS_FreeCString(mContext, string);
    JS_FreeValue(mContext, evalRes);
  } };

  std::string_view view{ string };
  res->reserve(view.size());

  std::copy(view.begin(), view.end(), std::back_inserter(*res));

  return res;
}

/*
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
        channel->Log(std::string_view{ exceptionCString.get() });
      }
    }
  }
  args.rval().setNull();
  return true;
}


Expected<JSFunction *, std::string>
AppScriptingInstance::SourceBreakpointCondition(u32 breakpointId, std::string_view condition) noexcept
{
  JSAutoRealm ar(mContext, GetRuntimeGlobal());
  ASSERT(::js::GetContextRealm(mContext), "Context realm retrieval failed.");
  JS::EnvironmentChain envChain{ mContext, JS::SupportUnscopables::Yes };
  if (envChain.length() != 0) {
    ASSERT(
      ::js::IsObjectInContextCompartment(envChain.chain()[0], mContext), "Object is not in context compartment.");
  }

  // Do the junk Gecko is supposed to do before calling into JSAPI.
  for (size_t i = 0; i < envChain.length(); ++i) {
    JS::ExposeObjectToActiveJS(envChain.chain()[i]);
  }
  constexpr auto argNames = std::to_array({ "tc", "task", "bp" });
  auto file = std::format("breakpoint:{}", breakpointId);
  auto fnName = std::format("bpCondition_{}", breakpointId);
  auto src = SourceFromString(mContext, condition);
  ASSERT(src.is_expected(), "expected source to have been constructed");
  DBGLOG(core, "source constructed: {} bytes", src.value().length());
  JS::RootedObject global(mContext, mGlobalObject);
  JS::CompileOptions options{ mContext };

  options.setFileAndLine("inline", breakpointId);

  JS::Rooted<JSFunction *> func{ mContext,
    JS::CompileFunction(
      mContext, envChain, options, fnName.c_str(), argNames.size(), argNames.data(), src.value()) };
  if (!func) {
    DBGLOG(core, "failed to compile event handler: {}", condition);
    return ConsumePendingException(mContext)
      .transform([](auto &&str) -> mdb::Unexpected<std::string> { return mdb::unexpected(std::move(str)); })
      .value_or(mdb::Unexpected{ std::string{ "Failed" } });
  }
  return expected<JSFunction *>(func.get());
}
*/
} // namespace mdb::js