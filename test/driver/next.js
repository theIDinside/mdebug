const { DAClient, MDB_PATH, testException, buildDirFile, getStackFramePc } = require("./client")

const da_client = new DAClient(MDB_PATH, []);

const expectedStackTraces = [
  [{ line: 39, name: "foo" }, { line: 46, name: "main" }, { line: 0, name: "unknown" }],
  [{ line: 33, name: "bar" }, { line: 40, name: "foo" }, { line: 46, name: "main" }, { line: 0, name: "unknown" }],
  [{ line: 14, name: "baz" }, { line: 34, name: "bar" }, { line: 40, name: "foo" }, { line: 46, name: "main" }, { line: 0, name: "unknown" }],
  [{ line: 7, name: "quux" }, { line: 16, name: "baz" }, { line: 34, name: "bar" }, { line: 40, name: "foo" }, { line: 46, name: "main" }, { line: 0, name: "unknown" }]
]

async function test() {
  await da_client.launchToMain(buildDirFile("stackframes"));
  const threads = await da_client.threads();
  const frames = await da_client.stackTrace(threads[0].id);
  const pc = getStackFramePc(frames, 0);
  const disassembly = await da_client.sendReqGetResponse("disassemble", { memoryReference: pc, offset: 0, instructionOffset: 0, instructionCount: 10, resolveSymbols: false });
  const allThreadsStop = true;
  const evt = await da_client.sendReqWaitEvent("next", { threadId: threads[0].id, singleThread: !allThreadsStop, granularity: "instruction" }, "stopped")
  if (evt.event != "stopped" || evt.body.reason != "step") {
    throw new Error(`Expected to see a 'stopped' event with 'step' as reason`);
  }
  if (evt.body.allThreadsStopped != allThreadsStop) {
    throw new Error(`Expected all threads to have stopped after step.`);
  }
  const next_pc = getStackFramePc(frames, 0);
  if (next_pc != disassembly.body.instructions[1].address) {
    throw new Error(`Expected to be at ${disassembly.body.instructions[1].address} but RIP=${next_pc}`);
  }
}

test().then(() => {
  console.log(`Test ${__filename} succeeded`);
  process.exit(0);
}).catch(testException);