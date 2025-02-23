/** LICENSE TEMPLATE */
#include "event_dispatcher.h"
#include "bpjs.h"
#include "common.h"
#include "events/event.h"
#include "events/stop_event.h"
#include "js/Object.h"
#include "js/TracingAPI.h"
#include "js/TypeDecls.h"
#include "js/Value.h"
#include "jsapi.h"
#include "mdbjs/mdbjs.h"
#include "mdbjs/taskinfojs.h"
#include "utils/logger.h"
#include <supervisor.h>
#include <task.h>
#include <utility>

namespace mdb::js {

void
EventDispatcher::Init() noexcept
{
  JSContext *cx = mRuntime->GetRuntimeContext();
  JS::RootedObject global(cx, mRuntime->GetRuntimeGlobal());

  JS::RootedValue mdbRootedValue(cx);

  // Retrieve the "mdb" property from the global object
  if (!JS_GetProperty(cx, global, "mdb", &mdbRootedValue)) {
    PANIC("Failed to retrieve the 'mdb' property from the global object");
  }

  // Ensure the value is an object
  if (!mdbRootedValue.isObject()) {
    PANIC("'mdb' is not an object");
  }

  // Get the JSObject from the value
  JS::RootedObject mdbObject(cx, &mdbRootedValue.toObject());

  JS::RootedObject events(cx, JS_NewObject(cx, &EventDispatcher::JsClass));

  if (!events) {
    PANIC("Failed to create proto for EventDispatcher");
  }

  JS_SetReservedSlot(events, GlobalSlot, JS::PrivateValue(this));

#define ITEM(VARIANT, ...)                                                                                        \
  if (!JS_DefineProperty(cx, events, #VARIANT, static_cast<int>(StopEvents::VARIANT),                             \
                         JSPROP_ENUMERATE | JSPROP_PERMANENT | JSPROP_READONLY)) {                                \
    PANIC("Failed to configure event enum StopEvents::" #VARIANT);                                                \
  }
  FOR_EACH_EVENT(ITEM)
#undef ITEM

  // Define the "on" method on the "debugger" object
  if (!JS_DefineFunctions(cx, events, EventDispatcherFunctions)) {
    PANIC("Failed to create .on listener subscriber function on events object");
  }

  // And finally, attach the events object to the global mdb object (thus getting mdb.events.on(mdb.events.clone,
  // () => ...) functionality)
  if (!JS_DefineProperty(cx, mdbObject, "events", events, JSPROP_ENUMERATE | JSPROP_PERMANENT | JSPROP_READONLY)) {
    PANIC("Failed to instantiate mdb.events in the ScriptRuntime");
  }

  DBGLOG(interpreter, "Regstering EventDispatcher sub system with trace system");
  mRuntime->AddTrace([this](JSTracer *trc) {
    for (auto &event : mSubscribers) {
      for (auto &cb : event) {
        JS::TraceEdge(trc, &cb, "event listener");
      }
    }
  });

  pub::breakpointHitEvent.Subscribe(
    SubscriberIdentity{this}, [this](TraceeController *tc, const Ref<mdb::TaskInfo> &taskInfo, u32 breakpointId) {
      const auto subs = GetSubscribers(StopEvents::breakpointHitEvent);
      if (subs.empty()) {
        return;
      }

      JSContext *cx = mRuntime->GetRuntimeContext();
      auto bp = tc->GetUserBreakpoints().GetUserBreakpoint(breakpointId);
      JS::Rooted<JSObject *> obj{cx, mdb::js::Breakpoint::Create(cx, std::move(bp))};

      for (auto &cb : subs) {
        JS::RootedValue jsfnVal(cx, JS::ObjectValue(*cb));
        JS::RootedValue rval(cx);

        // Prepare the arguments (two integers) and ensure they are rooted
        // Prepare the arguments
        JS::RootedValueVector args{cx};
        VERIFY(args.resize(2), "Failed to resize arg vector");

        JS::Rooted<JSObject *> task(cx, js::TaskInfo::Create(cx, taskInfo));
        args[0].setObject(*obj);
        args[1].setObject(*task);

        // Create a handle array for the arguments
        if (!JS_CallFunctionValue(cx, nullptr, jsfnVal, args, &rval)) {
          DBGLOG(interpreter, "Failed to call function for event {}", "breakpointHitEvent");
        } else {
          DBGLOG(interpreter, "Called callback for event {} successfully", "breakpointHitEvent");
        }
      }
    });

  pub::clone.Subscribe(SubscriberIdentity{this},
                       [](TraceeController *tc, const Ref<mdb::TaskInfo> &task, Tid tid) {});
}

EventDispatcher::EventDispatcher(mdb::js::AppScriptingInstance *runtime) noexcept : mRuntime(runtime) {}

/* static */
EventDispatcher *
EventDispatcher::Create(mdb::js::AppScriptingInstance *instance) noexcept
{
  JS::RootedObject global(instance->GetRuntimeContext(), instance->GetRuntimeGlobal());
  auto eventDispatcher = new EventDispatcher{instance};
  eventDispatcher->Init();
  return eventDispatcher;
}

/* static */
bool
EventDispatcher::JS_Once(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  TODO(__PRETTY_FUNCTION__);
}

// JavaScript bindings for the `on` method
/* static */
bool
EventDispatcher::JS_On(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
  if (argc != 2 || !args[0].isNumber()) {
    JS_ReportErrorASCII(cx, "Usage: debugger.on(mdb.events.eventName, callback)");
    return false;
  }

  // Validate argument 1 is a callable object
  if (!args[1].isObject() || !JS::IsCallable(&args[1].toObject())) {
    JS_ReportErrorASCII(cx, "Second argument must be a callable object.");
    return false;
  }

  // Extract the string and callable
  int eventNumber = args[0].toInt32();
  auto event = Enum<StopEvents>::FromInt(eventNumber);

  if (!event) {
    JS_ReportErrorASCII(cx, "Invalid event id %d", eventNumber);
    return false;
  }

  DBGLOG(interpreter, "attempt to add subscriber to StopEvents::{}", *event);

  JS::RootedObject callable(cx, &args[1].toObject());
  ASSERT(callable, "failed to root callable");
  JS::RootedObject callee(cx, &args.thisv().toObject());

  ASSERT(callee, "failed to get global object!");

  auto *retval = JS::GetMaybePtrFromReservedSlot<EventDispatcher>(callee, GlobalSlot);
  ASSERT(retval, "Failed to retrieve event dispatcher");
  if (retval->mSubscribers[std::to_underlying(*event)].empty()) {
    retval->mSubscribers[std::to_underlying(*event)] = {};
  }
  retval->mSubscribers[std::to_underlying(*event)].emplace_back(callable);

  DBGLOG(interpreter, "Added event listener to {}", *event);

  args.rval().setUndefined();
  return true;
}

EventResult
EventDispatcher::EmitCloneEvent(TraceeController *supervisor, Ref<mdb::TaskInfo> task, int newTid) noexcept
{
  JSContext *cx = mRuntime->GetRuntimeContext();
  for (auto &cb : mSubscribers[std::to_underlying(StopEvents::clone)]) {
    JS::RootedValue jsfnVal(cx, JS::ObjectValue(*cb));
    JS::RootedValue rval(cx);

    // Prepare the arguments (two integers) and ensure they are rooted
    // Prepare the arguments
    JS::RootedValueVector args{cx};
    VERIFY(args.resize(2), "Failed to resize arg vector");
    args[0].setInt32(task->mTid);
    args[1].setInt32(newTid);

    // Create a handle array for the arguments
    if (!JS_CallFunctionValue(cx, nullptr, jsfnVal, args, &rval)) {
      DBGLOG(interpreter, "Failed to call function for event {}", "clone");
    } else {
      DBGLOG(interpreter, "Called callback for event {} successfully", "clone");
    }
  }
  TODO("EventDispatcher::EmitCloneEvent");
}

EventResult
EventDispatcher::EmitExecEvent(TraceeController *supervisor, Ref<mdb::TaskInfo> task,
                               std::string execedFile) noexcept
{
  TODO(__PRETTY_FUNCTION__);
}

EventResult
EventDispatcher::EmitBreakpointEvent(TraceeController *supervisor, Ref<mdb::TaskInfo> task,
                                     u32 breakpointId) noexcept
{
  TODO(__PRETTY_FUNCTION__);
}

EventResult
EventDispatcher::EmitSignalEvent(TraceeController *supervisor, Ref<mdb::TaskInfo> task, u32 signalNumber) noexcept
{
  TODO(__PRETTY_FUNCTION__);
}

EventResult
EventDispatcher::EmitStoppedAllEvent(TraceeController *supervisor) noexcept
{
  TODO(__PRETTY_FUNCTION__);
}

std::span<JS::Heap<JSObject *>>
EventDispatcher::GetSubscribers(StopEvents event) noexcept
{
  return mSubscribers[std::to_underlying(event)];
}

} // namespace mdb::js
#undef FOR_EACH