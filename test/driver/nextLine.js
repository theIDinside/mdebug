const { DAClient, MDB_PATH, buildDirFile, readFile, runTest, repoDirFile, getLineOf } =
  require("./client")(__filename);

const da_client = new DAClient(MDB_PATH, [], false);

async function test() {
  await da_client.launchToMain(buildDirFile("stackframes"));
  const file = readFile(repoDirFile("test/stackframes.cpp"));
  const bp_lines = ["BPLine1"]
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }));
  const threads = await da_client.threads();
  await da_client
    .sendReqGetResponse("setBreakpoints", {
      source: {
        name: repoDirFile("test/stackframes.cpp"),
        path: repoDirFile("test/stackframes.cpp"),
      },
      breakpoints: bp_lines,
    });
  await da_client.contNextStop(threads[0].id);
  let frames = await da_client.stackTrace(threads[0].id);
  const start_line = frames.body.stackFrames[0].line;
  const allThreadsStop = true;
  const evt = await da_client.sendReqWaitEvent(
    "next",
    {
      threadId: threads[0].id,
      singleThread: !allThreadsStop,
      granularity: "line",
    },
    "stopped",
    1000
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
  {
    frames = await da_client.stackTrace(threads[0].id);
    const end_line = frames.body.stackFrames[0].line;
    if (end_line != start_line + 1) {
      throw new Error(`Expected to be at line ${start_line + 1} but we're at line ${end_line}`);
    }
    console.log(`at correct line ${end_line}`);
  }

  const evt2 = await da_client.sendReqWaitEvent(
    "next",
    {
      threadId: threads[0].id,
      singleThread: !allThreadsStop,
      granularity: "line",
    },
    "stopped",
    1000
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
  {
    frames = await da_client.stackTrace(threads[0].id);
    const end_line = frames.body.stackFrames[0].line;
    if (end_line != start_line + 2) {
      throw new Error(`Expected to be at line ${start_line + 2} but we're at line ${end_line}`);
    }
    console.log(`at correct line ${end_line}`);
  }

}

runTest(test);
