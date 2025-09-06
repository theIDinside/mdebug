/** LICENSE TEMPLATE */
#include "mdbjs.h"

// mdb
#include <common.h>
#include <lib/arena_allocator.h>
#include <mdbjs/supervisorjs.h>
#include <mdbjs/taskinfojs.h>
#include <mdbjs/util.h>
#include <utils/logger.h>

// system
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

/* static */ JSValue
Scripting::GetSupervisor(JSContext *ctx, JSValueConst thisValue, int argCount, JSValueConst *argv) noexcept
{
  (void)ctx;
  (void)thisValue;
  (void)argCount;
  (void)argv;
  return JS_UNDEFINED;
}

/* static */ JSValue
Scripting::Log(JSContext *ctx, [[maybe_unused]] JSValueConst thisValue, int argCount, JSValueConst *argv) noexcept
{
  if (argCount < 1) {
    return JS_UNDEFINED;
  }
  if (JS_IsString(argv[0])) {
    QuickJsString string = QuickJsString::FromValue(ctx, argv[0]);
    DBGLOG_STR(interpreter, string.mString);
  } else {
    DBGLOG(warning, "Discarding parameter to log. It must be a string.");
  }
  return JS_UNDEFINED;
}

/* static */ JSValue
Scripting::GetTask(
  JSContext *ctx, [[maybe_unused]] JSValueConst thisValue, int argCount, JSValueConst *argv) noexcept
{
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
Scripting::PrintThreads(
  JSContext *ctx, [[maybe_unused]] JSValueConst thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
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
Scripting::PrintProcesses(
  JSContext *ctx, [[maybe_unused]] JSValueConst thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  alloc::StackBufferResource<4096> alloc;
  std::pmr::string buffer{ &alloc };
  buffer.reserve(4096);

  auto iterator = std::back_inserter(buffer);
  for (auto supervisor : Tracer::Get().GetAllProcesses()) {
    iterator = ToString(iterator, supervisor);
    *iterator++ = '\n';
  }

  auto v = JS_NewStringLen(ctx, buffer.data(), buffer.size());
  return v;
}

/* static */ JSValue
Scripting::Help(JSContext *ctx, [[maybe_unused]] JSValueConst thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
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

  for (const FunctionDescriptor &descriptor : FunctionDescriptors()) {
    fn = JS_NewCFunction(mContext, descriptor.mFn, descriptor.mName.data(), descriptor.mArgCount);
    JS_SetPropertyStr(mContext, mdbObject, descriptor.mName.data(), fn);
  }

  JSValue globalObject = JS_GetGlobalObject(mContext);
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

  JSValue evalRes = JS_Eval(mContext, input.data(), input.size(), "<eval>", 0);

  auto jsString = JS_ToString(mContext, evalRes);
  auto string = JS_ToCString(mContext, jsString);

  ScopedDefer defer{ [&]() {
    JS_FreeValue(mContext, jsString);
    JS_FreeCString(mContext, string);
    JS_FreeValue(mContext, evalRes);
  } };

  std::string_view view{ string };

  CopyTo(view, *res);

  return res;
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