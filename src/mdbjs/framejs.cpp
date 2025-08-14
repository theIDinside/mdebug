#include "framejs.h"
#include "mdbjs/jsobject.h"
#include "mdbjs/variablejs.h"
#include "quickjs/quickjs.h"
#include "supervisor.h"
#include "symbolication/callstack.h"
#include <symbolication/objfile.h>

namespace mdb {

bool
FrameLookupHandle::IsValid() noexcept
{
  return !mTask->VariableReferenceIsStale(mFrame.FrameId());
}

} // namespace mdb

namespace mdb::js {

static inline constexpr JSValue
ThrowFrameNotAlive(JSContext *context)
{
  return JS_ThrowTypeError(context, "Frame handle was null (frame no longer alive)");
}

static constexpr auto FrameNotAliveErrorMessage = "Frame handle was null (frame no longer alive)";

JSValue
Frame::Id(JSContext *context, JSValue thisValue, int argCount, JSValue *argv)
{
  auto *handle = GetThisOrReturnException(handle, FrameNotAliveErrorMessage);
  return JS_NewUint32(context, static_cast<u32>(handle->mFrame.FrameId()));
}

static JSValue
GetArrayOfVariables(JSContext *context,
  SymbolFile *symbolFile,
  TraceeController *supervisor,
  sym::Frame &frame,
  sym::VariableSet set)
{
  auto arrayObject = JS_NewArray(context);

  auto variables = symbolFile->GetVariables(*supervisor, frame, set);
  for (auto &&[index, variable] : std::ranges::views::enumerate(variables)) {
    auto jsValue = JsVariable::CreateValue(context, std::move(variable));
    JS_SetPropertyUint32(context, arrayObject, index, jsValue);
  }

  return arrayObject;
}

JSValue
Frame::Locals(JSContext *context, JSValue thisValue, int argCount, JSValue *argv)
{
  auto *frame = GetThisOrReturnException(frame, "Could not retrieve frame handle");

  if (!frame->IsValid()) {
    return JS_ThrowReferenceError(context,
      "Frame is no longer valid for %s. Request new stack frames adn variables",
      frame->mFrame.CStringName().value_or("<unknown frame name>"));
  }
  auto symbolFile = frame->mFrame.GetSymbolFile();
  ASSERT(symbolFile, "No symbol file for frame!");
  auto supervisor = frame->mTask->GetSupervisor();
  ASSERT(supervisor, "Could not get supervisor from task!");

  return GetArrayOfVariables(context, symbolFile, supervisor, frame->mFrame, sym::VariableSet::Locals);
};

JSValue
Frame::Arguments(JSContext *context, JSValue thisValue, int argCount, JSValue *argv)
{
  auto *frame = GetThisOrReturnException(frame, "Could not retrieve frame handle");

  if (!frame->IsValid()) {
    return JS_ThrowReferenceError(context,
      "Frame is no longer valid for %s. Request new stack frames adn variables",
      frame->mFrame.CStringName().value_or("<unknown frame name>"));
  }
  auto symbolFile = frame->mFrame.GetSymbolFile();
  ASSERT(symbolFile, "No symbol file for frame!");
  auto supervisor = frame->mTask->GetSupervisor();
  ASSERT(supervisor, "Could not get supervisor from task!");

  return GetArrayOfVariables(context, symbolFile, supervisor, frame->mFrame, sym::VariableSet::Arguments);
};

JSValue
Frame::Caller(JSContext *context, JSValue thisValue, int argCount, JSValue *argv)
{
  return JS_ThrowTypeError(context,
    "Caller"
    " method not implemented");
};

JSValue
Frame::Name(JSContext *context, JSValue thisValue, int argCount, JSValue *argv)
{
  auto *frame = GetThisOrReturnException(frame, "Could not retrieve frame handle");
  return JS_NewStringLen(context, frame->mFrame.Name()->data(), frame->mFrame.Name()->length());
}

} // namespace mdb::js
