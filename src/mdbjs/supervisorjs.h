/** LICENSE TEMPLATE */

#include <interface/tracee_command/supervisor_state.h>
#include <mdbjs/jsobject.h>

namespace mdb::js {

template <typename Out, typename Supervisor>
constexpr Out
ToString(Out iteratorLike, Supervisor *supervisor)
{
  return std::format_to(iteratorLike,
    "supervisor {}: threads={}, exited={}",
    supervisor->TaskLeaderTid(),
    supervisor->ThreadsCount(),
    supervisor->IsExited());
}

struct JsSupervisor : public JSBinding<JsSupervisor, tc::SupervisorState, JavascriptClasses::Supervisor>
{
  static auto Id(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) -> JSValue;
  static auto ToString(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) -> JSValue;
  static auto Breakpoints(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) -> JSValue;

  static constexpr std::span<const JSCFunctionListEntry>
  PrototypeFunctions() noexcept
  {
    static constexpr JSCFunctionListEntry funcs[] = { /** Method definitions */
      FunctionEntry("id", 0, &Id),
      FunctionEntry("toString", 0, &ToString),
      FunctionEntry("breakpoints", 0, &Breakpoints),
      ToStringTag("Supervisor")
    };
    return funcs;
  }
};
} // namespace mdb::js