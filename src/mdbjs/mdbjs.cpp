/** LICENSE TEMPLATE */
#include "mdbjs.h"
#include "utils/scoped_fd.h"

// mdb
#include <common.h>
#include <lib/arena_allocator.h>
#include <mdbjs/supervisorjs.h>
#include <mdbjs/taskinfojs.h>
#include <mdbjs/util.h>
#include <mdbjs/value_resolver_registry.h>
#include <session_task_map.h>
#include <tracer.h>
#include <utils/logger.h>

// system
#include <cstdlib>
#include <filesystem>
#include <limits.h>
#include <unistd.h>

// dependency
#include <mdbjs/include-quickjs.h>

#define STATIC_INIT_CHECK(Message)                                                                                \
  static bool constantsInitialized = false;                                                                       \
  ScopedDefer defer = []() { constantsInitialized = true; };                                                      \
  MDB_ASSERT(!constantsInitialized, Message)

namespace mdb::js {

Scripting *Scripting::sInstance = nullptr;

/* static */
std::optional<JavascriptException>
JavascriptException::GetException(JSContext *context) noexcept
{
  if (!context) {
    return std::nullopt;
  }

  if (!JS_HasException(context)) {
    return std::nullopt;
  }

  JSValue exceptionValue = JS_GetException(context);
  if (JS_IsUndefined(exceptionValue)) {
    return std::nullopt;
  }

  JavascriptException ex;

  // Error message
  const auto *exceptionMsg = JS_ToCString(context, exceptionValue);
  if (exceptionMsg) {
    ex.mExceptionMessage = exceptionMsg;
    JS_FreeCString(context, exceptionMsg);
  }

  // Stack trace
  auto stackValue = JS_GetProperty(context, exceptionValue, (JSAtom)StaticAtom::JSstack);
  if (!JS_IsUndefined(stackValue)) {
    const auto *stackTraceString = JS_ToCString(context, stackValue);
    if (stackTraceString) {
      ex.mStackTrace = stackTraceString;
      JS_FreeCString(context, stackTraceString);
    }
    JS_FreeValue(context, stackValue);
  }

  // File name
  auto fileValue = JS_GetProperty(context, exceptionValue, (JSAtom)StaticAtom::JSfileName);
  if (!JS_IsUndefined(fileValue)) {
    const auto *fileNameString = JS_ToCString(context, fileValue);
    if (fileNameString) {
      ex.mFileName = fileNameString;
      JS_FreeCString(context, fileNameString);
    }
    JS_FreeValue(context, fileValue);
  }

  // Line number
  auto lineValue = JS_GetProperty(context, exceptionValue, (JSAtom)StaticAtom::JSlineNumber);
  if (JS_IsNumber(lineValue)) {
    JS_ToInt32(context, &ex.mLineNumber, lineValue);
  }
  JS_FreeValue(context, lineValue);

  // Column number
  auto columnValue = JS_GetProperty(context, exceptionValue, (JSAtom)StaticAtom::JScolumnNumber);
  if (JS_IsNumber(columnValue)) {
    JS_ToInt32(context, &ex.mColumn, columnValue);
  }
  JS_FreeValue(context, columnValue);
  JS_FreeValue(context, exceptionValue);

  return ex;
}

Scripting::Scripting(JSRuntime *runtime, JSContext *context) noexcept
    : mRuntime(runtime), mContext(context),
      mBumpAllocator(alloc::ArenaResource::CreateUniquePtr(alloc::Page{ 32 })),
      mRegistry(ResolverRegistry::Init(context))
{
}

/* static */ JSValue
Scripting::GetSupervisor(JSContext *cx, JSValueConst thisValue, int argCount, JSValueConst *argv) noexcept
{
  (void)cx;
  (void)thisValue;
  (void)argCount;
  (void)argv;
  return JS_UNDEFINED;
}

/* static */ JSValue
Scripting::GetSupervisors(
  JSContext *cx, [[maybe_unused]] JSValueConst thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  auto arrayValue = JS_NewArray(cx);

  auto index = 0;
  const auto procs = Tracer::Get().GetAllProcesses();
  for (tc::SupervisorState *supervisor : procs) {
    auto supervisorValue = JsSupervisor::CreateValue(cx, supervisor);
    JS_SetPropertyUint32(cx, arrayValue, index++, supervisorValue);
  }

  return arrayValue;
}

/* static */ JSValue
Scripting::Log(JSContext *cx, [[maybe_unused]] JSValueConst thisValue, int argCount, JSValueConst *argv) noexcept
{
  if (argCount < 1) {
    return JS_UNDEFINED;
  }
  if (JS_IsString(argv[0])) {
    QuickJsString string = QuickJsString::FromValue(cx, argv[0]);
    DBGLOG_STR(interpreter, string.mString);
  } else {
    DBGLOG(warning, "Discarding parameter to log. It must be a string.");
  }
  return JS_UNDEFINED;
}

/* static */ JSValue
Scripting::GetTask(
  JSContext *cx, [[maybe_unused]] JSValueConst thisValue, int argCount, JSValueConst *argv) noexcept
{
  if (argCount < 0 || !JS_IsNumber(argv[0])) {
    return JS_ThrowTypeError(cx, Scripting::HelpMessage("getThread").data());
  }

  i32 tid = -1;
  if (JS_ToInt32(cx, &tid, argv[0])) {
    return JS_ThrowTypeError(cx, "number conversion failed.");
  }

  auto taskInfo = Tracer::GetThreadByTidOrDebugId(tid);
  if (!taskInfo) {
    JS_UNDEFINED;
  }

  return JsTaskInfo::CreateValue(cx, taskInfo);
}

/* static */
JSValue
Scripting::GetThreads(
  JSContext *cx, [[maybe_unused]] JSValueConst thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  JSValueConst value = JS_NewArray(cx);

  auto index = 0;
  for (auto &[id, thread] : Tracer::GetSessionTaskMap().AllThreads()) {
    auto task = JsTaskInfo::CreateValue(cx, thread);
    JS_SetPropertyUint32(cx, value, index++, task);
  }

  return value;
}

/* static */ JSValue
Scripting::PrintThreads(
  JSContext *cx, [[maybe_unused]] JSValueConst thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  auto scopedTemporary = sInstance->mBumpAllocator->ScopeAllocation();

  std::pmr::string buffer{ scopedTemporary.GetAllocator() };
  buffer.reserve(4096);

  auto iterator = std::back_inserter(buffer);
  for (auto *supervisor : Tracer::Get().GetAllProcesses()) {
    iterator = ToString(iterator, supervisor);
    *iterator++ = '\n';

    for (const auto &t : supervisor->GetThreads()) {
      iterator = ToString(iterator, t);
      *iterator++ = '\n';
    }
    iterator = std::format_to(iterator, "----------\n");
  }

  auto v = JS_NewStringLen(cx, buffer.data(), buffer.size());
  return v;
}

/* static */ JSValue
Scripting::PrintProcesses(
  JSContext *cx, [[maybe_unused]] JSValueConst thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  auto scopedTemporary = sInstance->mBumpAllocator->ScopeAllocation();
  std::pmr::string buffer{ scopedTemporary.GetAllocator() };
  buffer.reserve(4096);

  auto iterator = std::back_inserter(buffer);
  for (auto *supervisor : Tracer::Get().GetAllProcesses()) {
    iterator = ToString(iterator, supervisor);
    *iterator++ = '\n';
  }

  auto v = JS_NewStringLen(cx, buffer.data(), buffer.size());
  return v;
}

/* static */ JSValue
Scripting::Help(JSContext *cx, [[maybe_unused]] JSValueConst thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  auto msg = HelpMessage();
  return JS_NewStringLen(cx, msg.data(), msg.size());
}

/* static */ JSValue
Scripting::RegisterResolver(
  JSContext *cx, [[maybe_unused]] JSValueConst thisValue, int argCount, JSValueConst *argv) noexcept
{
  if (argCount < 2) {
    return JS_ThrowTypeError(cx, "Invalid args: requires ({name, match, objectFileName}, resolveApplyFn)");
  }

  if (!JS_IsObject(argv[0])) {
    return JS_ThrowTypeError(
      cx, "Invalid args: first argument must be an object containing name and match fields of type string");
  }

  // Validate that the object contains 'name' and 'match' fields of type string

  constexpr static std::string_view fields[]{ "name"sv, "match"sv, "objectFileName"sv };

  std::array<StackValue, 3> properties;
  std::ranges::transform(fields, properties.begin(), [&](const auto &name) {
    return StackValue::GetPropertyString(cx, argv[0], name.data());
  });

  for (const auto &[index, prop] : std::ranges::enumerate_view{ properties }) {
    if (JS_IsUndefined(prop)) {
      return JS_ThrowTypeError(cx, "Invalid args: object must contain a '%s' field", fields[index].data());
    }
    if (!JS_IsString(prop)) {
      return JS_ThrowTypeError(cx, "Invalid args: '%s' field must be of type string", fields[index].data());
    }
  }

  if (!JS_IsFunction(cx, argv[1])) {
    return JS_ThrowTypeError(
      cx, "Invalid args: second argument must be a function that returns an array of JsVariables");
  }

  auto name = QuickJsString::FromValue(cx, properties[0]);
  auto match = QuickJsString::FromValue(cx, properties[1]);
  auto fileName = QuickJsString::FromValue(cx, properties[2]);

  Get().mRegistry->RegisterResolver(fileName.mString, name.mString, match.mString, argv[1]);

  return JS_UNDEFINED;
}

/* static */ JSValue
Scripting::LoadScript(
  JSContext *cx, [[maybe_unused]] JSValueConst thisValue, int argCount, JSValueConst *argv) noexcept
{
  if (argCount < 1) {
    return JS_ThrowTypeError(cx, "Invalid args: loadScript requires a file path argument");
  }

  if (!JS_IsString(argv[0])) {
    return JS_ThrowTypeError(cx, "Invalid args: file path must be a string");
  }

  auto pathString = QuickJsString::FromValue(cx, argv[0]);
  ScopedFd f = ScopedFd::Open(pathString.mString);
  MemoryMapping data = f.MemoryMap<char>();

  if (!data.IsOpen()) {
    return JS_ThrowTypeError(cx, "Failed to open file: %s", pathString.mString.data());
  }

  StackValue result = StackValue::Eval(cx, data.Data(), data.FileContentsLength(), pathString.mString.data());

  if (JS_IsException(result)) {
    return result.Throw();
  };

  return JS_UNDEFINED;
}

/* static */ std::optional<Path>
Scripting::GetConfigFilePath(bool useXdg) noexcept
{
  if (useXdg) {
    // Try XDG_CONFIG_HOME first
    const char *xdgConfigHome = std::getenv("XDG_CONFIG_HOME");
    if (xdgConfigHome && xdgConfigHome[0] != '\0') {
      return Path{ xdgConfigHome } / "mdb" / "mdbinit.js";
    }

    // Fallback to ~/.config
    const char *home = std::getenv("HOME");
    if (home && home[0] != '\0') {
      return Path{ home } / ".config" / "mdb" / "mdbinit.js";
    }
    return std::nullopt;
  }

  // Get executable directory
  char exePath[PATH_MAX];
  ssize_t len = readlink("/proc/self/exe", exePath, sizeof(exePath) - 1);
  if (len == -1) {
    return std::nullopt;
  }
  exePath[len] = '\0';
  Path p{ exePath };
  return p.parent_path() / "config" / "mdbinit.js";
}

/* static */ void
Scripting::TryLoadConfigFile(const Path &configPath) noexcept
{
  namespace fs = std::filesystem;

  // Silently skip if file doesn't exist
  if (!fs::exists(configPath)) {
    return;
  }

  DBGLOG(interpreter, "Loading config file: {}", configPath.string());

  // Open the config file
  ScopedFd f = ScopedFd::Open(configPath);
  if (!f.IsOpen()) {
    DBGLOG(warning, "Failed to open config file: {}", configPath.string());
    return;
  }

  // Memory map the file
  MemoryMapping data = f.MemoryMap<char>();
  if (!data.IsOpen()) {
    DBGLOG(warning, "Failed to memory map config file: {}", configPath.string());
    return;
  }

  // Execute the script
  StackValue result =
    StackValue::Eval(Get().mContext, data.Data(), data.FileContentsLength(), configPath.string().c_str());

  // Check for JavaScript exceptions
  if (JS_IsException(result)) {
    if (auto ex = JavascriptException::GetException(Get().mContext)) {
      DBGLOG(warning, "Error in config file {}: {}", configPath.string(), ex->mExceptionMessage);
      if (!ex->mStackTrace.empty()) {
        DBGLOG(interpreter, "Stack trace:\n{}", ex->mStackTrace);
      }
    }
  }
}

/* static */ void
Scripting::LoadConfigFiles() noexcept
{
  // Load XDG config first
  if (auto xdgPath = GetConfigFilePath(true)) {
    TryLoadConfigFile(*xdgPath);
  }

  // Load executable directory config second
  if (auto exePath = GetConfigFilePath(false)) {
    TryLoadConfigFile(*exePath);
  }
}

void
Scripting::InitializeTypes() noexcept
{
  STATIC_INIT_CHECK("Double initialization of types");

  for (const auto &metaData : MdbJavascriptTypes::GetAll()) {
    DBGLOG(core, "Initializing JS Type {}", metaData.mType);
    metaData.mRegister(mContext);
  }
}

void
Scripting::InitModuleConstants(JSValue moduleObject) noexcept
{
  STATIC_INIT_CHECK("Double initialization of constants");

  for (const auto channel : Enum<Channel>::Variants()) {
    JS_DefinePropertyValueStr(mContext,
      moduleObject,
      Enum<Channel>::ToString(channel).data(),
      JS_NewInt32(mContext, std::to_underlying(channel)),
      JS_PROP_C_W_E);
  }
}

void
Scripting::InitializeMdbModule() noexcept
{
  STATIC_INIT_CHECK("Double initialization of module");

  JSValue mdbObject = JS_NewObject(mContext);

  JSValue fn;

  // We duplicate global script objects to both this.foo and mdb.foo, if the user wants to overwrite
  // this.foo to be something they want to use instead. That way mdb.foo is always safe.
  JSValue globalObject = JS_GetGlobalObject(mContext);
  for (const FunctionDescriptor &descriptor : FunctionDescriptors()) {
    fn = JS_NewCFunction(mContext, descriptor.mFn, descriptor.mName.data(), descriptor.mArgCount);
    JS_SetPropertyStr(mContext, mdbObject, descriptor.mName.data(), fn);

    // Duplicate for global scope
    JS_DupValue(mContext, fn);
    JS_SetPropertyStr(mContext, globalObject, descriptor.mName.data(), fn);
  }

  JS_SetPropertyStr(mContext, globalObject, "mdb", mdbObject);
  InitModuleConstants(mdbObject);
  JS_FreeValue(mContext, globalObject);
  constantsInitialized = true;
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
  sInstance->InitializeTypes();
  return sInstance;
}

/* static */
Scripting &
Scripting::Get() noexcept
{
  return *sInstance;
}

/* static */
alloc::ArenaResource *
Scripting::GetAllocator() noexcept
{
  return Get().mBumpAllocator.get();
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
  std::pmr::string *res = allocator->new_object<std::pmr::string>();

  StackValue evalRes = StackValue::Eval(mContext, input.data(), input.size(), "<eval>", 0);
  if (JS_IsException(evalRes)) {
    ExceptionToPrintableOutput(*res);
    return res;
  }

  StackValue jsString = evalRes.ToString();
  const auto string = QuickJsString::FromValue(mContext, jsString);
  CopyTo(string.mString, *res);

  return res;
}

bool
Scripting::ExceptionToPrintableOutput(std::pmr::string &result) noexcept
{
  if (!JS_HasException(mContext)) {
    return false;
  }

  JSValue exception = JS_GetException(mContext);

  const char *exceptionString = JS_ToCString(mContext, exception);
  const std::string_view msg{ exceptionString ? exceptionString : "<unknown exception>" };
  CopyTo(msg, result);

  if (JS_IsError(mContext, exception)) {
    result.push_back('\n');
    JSValue stack = JS_GetPropertyStr(mContext, exception, "stack");
    if (!JS_IsUndefined(stack)) {
      const char *exceptionStackString = JS_ToCString(mContext, stack);
      const std::string_view msg{ exceptionStackString ? exceptionStackString : "<error converting stack>" };
      CopyTo(msg, result);

      JS_FreeCString(mContext, exceptionStackString);
    }
    JS_FreeValue(mContext, stack);
  }

  JS_FreeCString(mContext, exceptionString);
  JS_FreeValue(mContext, exception);

  return true;
}

std::expected<JSValue, JavascriptException>
CallFunction(JSContext *context, JSValue functionValue, JSValue thisValue, std::span<JSValue> arguments)
{
  JSValue returnValue = JS_Call(context, functionValue, thisValue, arguments.size(), arguments.data());

  if (auto ex = JavascriptException::GetException(context); ex) {
    JS_FreeValue(context, returnValue);
    DBGLOG(core, "exception in js engine: {}\nStack trace:\n{}", ex->mExceptionMessage, ex->mStackTrace);
    return std::unexpected(std::move(ex.value()));
  }

  return returnValue;
}
} // namespace mdb::js