const {
  DAClient,
  MDB_PATH,
  buildDirFile,
  checkResponse,
  getLineOf,
  readFile,
  repoDirFile,
  runTest,
  seconds,
} = require("./client")(__filename);

const da_client = new DAClient(MDB_PATH, []);

const frame_pcs = [0x405c9d, 0x405cec, 0x405d2d, 0x405f31, 0x4036d4, 0x403785];
const frame_lines = [17, 25, 31, 52, 20, 27]

const sharedObjectsCount = 6;

async function set_bp(source, bps) {
  const file = readFile(repoDirFile(source));
  const bp_lines = bps
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }));
  return da_client.sendReqGetResponse("setBreakpoints", {
    source: {
      name: repoDirFile(source),
      path: repoDirFile(source),
    },
    breakpoints: bp_lines,
  });
}

async function test() {
  let modules_event_promise = da_client.prepareWaitForEventN("module", 6, 2000);
  await da_client.launchToMain(buildDirFile("stupid_shared"));
  const res = await modules_event_promise;

  if (res.length != sharedObjectsCount) {
    throw new Error(`Expected to see 6 module events for shared objects but saw ${res.length}`);
  }
  const threads = await da_client.threads();
  const bps = await set_bp("test/todo.cpp", ["BP1"]);

  // hit breakpoint in todo.cpp
  await da_client.sendReqWaitEvent(
    "continue",
    { threadId: threads[0].id },
    "stopped",
    seconds(1)
  );
  await da_client.stackTrace(threads[0].id, 10000000).then((res) => {
    checkResponse(res, "stackTrace", true);
    const { stackFrames } = res.body;
    console.log(`${JSON.stringify(stackFrames, null, 2)}`);
  });
}

runTest(test);
