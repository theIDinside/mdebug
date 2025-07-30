/** LICENSE TEMPLATE */
#pragma once

#include "events/stop_event.h"
#include "js/Class.h"
#include "js/RootingAPI.h"
#include <common/macros.h>
#include <common/typedefs.h>
#include <jsapi.h>
#include <string>

class TraceeController;
class TaskInfo;

namespace mdb::js {

class AppScriptingInstance;

// EventDispatcher class to manage events
// Conceptually the global `mdb.events` in Javascript land.
class EventDispatcher
{
  AppScriptingInstance *mRuntime;
  std::array<std::vector<JS::Heap<JSObject *>>, Enum<StopEvents>::Count()> mSubscribers{};

  // Javascript Embedding
  enum Slots
  {
    GlobalSlot,
    SlotCount
  };

  // Javascript Exposed functions
  // events.on
  static bool JS_On(JSContext *cx, unsigned argc, JS::Value *vp) noexcept;
  static bool JS_Once(JSContext *cx, unsigned argc, JS::Value *vp) noexcept;

  // Javascript Type Definition
  /* The class of the global object. */

  static consteval JSClass
  CreateJsClass()
  {
    // c++ init, yay!
    JSClass result{};
    return result;
  }

  static constexpr JSClass JsClass = []() {
    JSClass result{};
    result.name = "Events";
    result.flags = JSCLASS_HAS_RESERVED_SLOTS(SlotCount);
    return result;
  }();

  static constexpr JSFunctionSpec EventDispatcherFunctions[] = {
    JS_FN("on", &EventDispatcher::JS_On, 2, 0), JS_FN("once", &EventDispatcher::JS_Once, 2, 0), JS_FS_END};

  EventDispatcher(mdb::js::AppScriptingInstance *runtime) noexcept;
  void Init() noexcept;

public:
  static EventDispatcher *Create(mdb::js::AppScriptingInstance *instance) noexcept;

  // JavaScript bindings for the `on` method

  EventResult EmitCloneEvent(TraceeController *supervisor, Ref<mdb::TaskInfo> task, int newTid) noexcept;
  EventResult EmitExecEvent(TraceeController *supervisor, Ref<mdb::TaskInfo> task,
                            std::string execedFile) noexcept;
  EventResult EmitBreakpointEvent(TraceeController *supervisor, Ref<mdb::TaskInfo> task,
                                  u32 breakpointId) noexcept;
  EventResult EmitSignalEvent(TraceeController *supervisor, Ref<mdb::TaskInfo> task, u32 signalNumber) noexcept;
  EventResult EmitStoppedAllEvent(TraceeController *supervisor) noexcept;
  std::span<JS::Heap<JSObject *>> GetSubscribers(StopEvents event) noexcept;
  std::unique_ptr<EventDispatcher> Create() noexcept;
  void AddSubscriber();
};
}; // namespace mdb::js