const { DAClient, MDB_PATH, buildDirFile, getStackFramePc, runTest } =
  require("./client")(__filename);

const da_client = new DAClient(MDB_PATH, []);

async function test() {
  await da_client.launchToMain(buildDirFile("stackframes"));
  const threads = await da_client.threads();
  let frames = await da_client.stackTrace(threads[0].id);
  const pc = getStackFramePc(frames, 0);
  const disassembly = await da_client.sendReqGetResponse("disassemble", {
    memoryReference: pc,
    offset: 0,
    instructionOffset: 0,
    instructionCount: 10,
    resolveSymbols: false,
  });
  const allThreadsStop = true;
  const evt = await da_client.sendReqWaitEvent(
    "next",
    {
      threadId: threads[0].id,
      singleThread: !allThreadsStop,
      granularity: "instruction",
    },
    "stopped",
    3000
  );

  if (evt.reason != "step") {
    throw new Error(
      `Expected to see a 'stopped' event with 'step' as reason. Got event ${JSON.stringify(
        evt
      )}`
    );
  }
  if (evt.allThreadsStopped != allThreadsStop) {
    throw new Error(`Expected all threads to have stopped after step.`);
  }
  frames = await da_client.stackTrace(threads[0].id);
  const next_pc = getStackFramePc(frames, 0);
  if (next_pc != disassembly.body.instructions[1].address) {
    throw new Error(
      `Expected to be at ${disassembly.body.instructions[1].address} but RIP=${next_pc} (previos pc: ${pc})`
    );
  }
}

runTest(test);