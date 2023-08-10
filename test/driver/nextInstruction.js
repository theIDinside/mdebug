const { DAClient, MDB_PATH, buildDirFile, getStackFramePc, runTestSuite } =
  require("./client")(__filename);



async function test() {
  const da_client = new DAClient(MDB_PATH, []);
  await da_client.launchToMain(buildDirFile("stackframes"));
  const threads = await da_client.threads();
  let frames = await da_client.stackTrace(threads[0].id);
  // await da_client.setInsBreakpoint("0x40121f");
  const pc = getStackFramePc(frames, 0);
  const disassembly = await da_client.sendReqGetResponse("disassemble", {
    memoryReference: pc,
    offset: 0,
    instructionOffset: 0,
    instructionCount: 10,
    resolveSymbols: false,
  });
  const allThreadsStop = true;
  // await da_client.contNextStop(threads[0].id);
  const { event_body, response } = await da_client.sendReqWaitEvent(
    "next",
    {
      threadId: threads[0].id,
      singleThread: !allThreadsStop,
      granularity: "instruction",
    },
    "stopped",
    1000
  );

  if (!response.success) throw new Error(`Request was unsuccessful: ${JSON.stringify(response)}`);

  if (event_body.reason != "step") {
    throw new Error(
      `Expected to see a 'stopped' event with 'step' as reason. Got event ${JSON.stringify(
        event_body
      )}`
    );
  }
  if (event_body.allThreadsStopped != allThreadsStop) {
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

const tests = {
  "oneInstruction": test
}

runTestSuite(tests);
