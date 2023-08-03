const {
  DAClient,
  MDB_PATH,
  buildDirFile,
  runTest,
  seconds,
  getLineOf,
  readFile,
  repoDirFile,
} = require("./client")(__filename);

const da_client = new DAClient(MDB_PATH, []);

async function test() {
  await da_client.launchToMain(buildDirFile("threads_shared"));
  let threads = await da_client.threads();
  const file = readFile(repoDirFile("test/threads_shared.cpp"));
  const bp_lines = ["BP1"]
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }));
  await da_client.sendReqGetResponse("setBreakpoints", {
    source: {
      name: repoDirFile("test/threads_shared.cpp"),
      path: repoDirFile("test/threads_shared.cpp"),
    },
    breakpoints: bp_lines,
  });

  await da_client.contNextStop(threads[0].id);
  threads = await da_client.threads();
  let frames = await da_client.stackTrace(threads[1].id, 1000);
  console.log(`next line for ${threads[1].id}: (${JSON.stringify(threads[1], null, 2)})`)
  const { event_body, response } = await da_client.sendReqWaitEvent(
    "next",
    {
      threadId: threads[1].id,
      singleThread: false,
      granularity: "line",
    },
    "stopped",
    500
  );

  if (!response.success) throw new Error(`Expected 'next' command to succeed; got ${JSON.stringify(response)}`);

  frames = await da_client.stackTrace(threads[0].id);
  const end_line = frames.body.stackFrames[0].line;
  if (end_line != bp_lines[0].line + 1) {
    throw new Error(`Expected to be at line ${bp_lines[0].line + 1} but we're at line ${end_line}: ${JSON.stringify(frames.body.stackFrames, null, 2)}`);
  }
}

runTest(test);
