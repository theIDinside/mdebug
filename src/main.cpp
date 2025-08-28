/** LICENSE TEMPLATE */
// mdb
#include <app.h>
#include <configuration/command_line.h>
#include <configuration/config.h>
#include <event_queue.h>
#include <interface/dap/interface.h>
#include <mdbjs/mdbjs.h>
#include <tracer.h>
#include <utils/thread_pool.h>

// mdblib
#include <json/json.h>

// std
// system

namespace mdb {
Tracer *Tracer::sTracerInstance = nullptr;
js::Scripting *Tracer::sScriptRuntime = nullptr;
JSContext *Tracer::sApplicationJsContext = nullptr;
int Tracer::sLastTraceEventTime = 0;

termios Tracer::sOriginalTty = {};
winsize Tracer::sTerminalWindowSize = {};
bool Tracer::sUsePTraceMe = true;
TracerProcess Tracer::sApplicationState = TracerProcess::Running;
ThreadPool *ThreadPool::sGlobalThreadPool = new ThreadPool{};
const char *ui::dap::DebugAdapterClient::gSocketPath = nullptr;
} // namespace mdb

// DO NOT MOVE. Declaration of MDB Javascript types. Initialization of the types happen during init of script
// runtime.
#include <mdbjs/js.init.h>

int
main(int argc, const char **argv, const char **envp)
{
  mdb::Start(argc, argv, envp);
  return 0;
}