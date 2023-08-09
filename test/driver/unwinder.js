const {
  DAClient,
  MDB_PATH,
  buildDirFile,
  checkResponse,
  getLineOf,
  readFile,
  repoDirFile,
  seconds,
  runTestSuite
} = require("./client")(__filename);

async function unwindFromSharedObject() {
  const da_client = new DAClient(MDB_PATH, []);

  const frame_pcs = [0x405c9d, 0x405cec, 0x405d2d, 0x405f31, 0x4036d4, 0x403785];
  const frame_lines = [17, 25, 31, 52, 20, 27]

  const sharedObjectsCount = 6;
  const so_addr = "0x7ffff7fbc189";
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

  await da_client.setInsBreakpoint(so_addr);
  await da_client.contNextStop();
  const frames = await da_client.stackTrace(threads[0].id, 10000000).then((res) => {
    checkResponse(res, "stackTrace", true);
    const { stackFrames } = res.body;
    console.log(`${JSON.stringify(stackFrames, null, 2)}`);
    return stackFrames;
  });
  verifyFrameIs(frames[0], "convert_kilometers_to_miles");
}

const INSIDE_BAR_PROLOGUE = "0x0000000000401270";
const INSIDE_BAR_EPILOGUE = "0x0000000000401292";

function verifyFrameIs(frame, name) {
  if (frame.name != name) {
    throw new Error(`Expected frame ${name} but got ${frame.name}`);
  }
}

async function insidePrologueTest() {
  const da_client = new DAClient(MDB_PATH, []);
  await da_client.launchToMain(buildDirFile("stackframes"));
  await da_client.setInsBreakpoint(INSIDE_BAR_PROLOGUE);
  await da_client.contNextStop();
  const frames = await da_client
    .stackTrace()
    .then(({ response_seq, command, type, success, body: { stackFrames } }) => {
      checkResponse({ type, success, command }, "stackTrace", true);
      let application_frames = 0;
      for (const f of stackFrames) {
        application_frames++;
        if (f.name == "main") {
          break;
        }
      }
      if (application_frames != 3)
        throw new Error(
          `We're exactly at the start of the first instruction of main - expecting only 3 frame but got ${stackFrames.length}: ${JSON.stringify(stackFrames)}`
        );
      else
        return stackFrames;
    });
  verifyFrameIs(frames[0], "bar");
  verifyFrameIs(frames[1], "foo");
  verifyFrameIs(frames[2], "main");
}

async function insideEpilogueTest() {
  const da_client = new DAClient(MDB_PATH, []);
  await da_client.launchToMain(buildDirFile("stackframes"));
  await da_client.setInsBreakpoint(INSIDE_BAR_EPILOGUE);
  await da_client.contNextStop();
  const frames = await da_client
    .stackTrace()
    .then(({ response_seq, command, type, success, body: { stackFrames } }) => {
      checkResponse({ type, success, command }, "stackTrace", true);
      let application_frames = 0;
      for (const f of stackFrames) {
        application_frames++;
        if (f.name == "main") {
          break;
        }
      }
      if (application_frames != 3)
        throw new Error(
          `We're exactly at the start of the first instruction of main - expecting only 3 frame but got ${stackFrames.length}: ${JSON.stringify(stackFrames)}`
        );
      else
        return stackFrames;
    });
  verifyFrameIs(frames[0], "bar");
  verifyFrameIs(frames[1], "foo");
  verifyFrameIs(frames[2], "main");
}



async function normalTest() {
  const expectedStackTraces = [
    [
      { line: 39, name: "foo" },
      { line: 46, name: "main" },
      { line: 0, name: "unknown" },
      { line: 0, name: "unknown" },
      { line: 0, name: "unknown" },
    ],
    [
      { line: 33, name: "bar" },
      { line: 40, name: "foo" },
      { line: 46, name: "main" },
      { line: 0, name: "unknown" },
      { line: 0, name: "unknown" },
      { line: 0, name: "unknown" },
    ],
    [
      { line: 14, name: "baz" },
      { line: 34, name: "bar" },
      { line: 40, name: "foo" },
      { line: 46, name: "main" },
      { line: 0, name: "unknown" },
      { line: 0, name: "unknown" },
      { line: 0, name: "unknown" },
    ],
    [
      { line: 7, name: "quux" },
      { line: 16, name: "baz" },
      { line: 34, name: "bar" },
      { line: 40, name: "foo" },
      { line: 46, name: "main" },
      { line: 0, name: "unknown" },
      { line: 0, name: "unknown" },
      { line: 0, name: "unknown" },
    ],
  ];

  const da_client = new DAClient(MDB_PATH, []);
  await da_client.launchToMain(buildDirFile("stackframes"));
  const disassembly = await da_client.sendReqGetResponse("disassemble", {
    memoryReference: "0x401210",
    offset: 0,
    instructionOffset: 0,
    instructionCount: 9,
    resolveSymbols: false,
  });
  if (disassembly.body.instructions.length != 9) {
    throw new Error(
      `Expected 4 disassembled instructions but instead got ${disassembly.body.instructions.length
      }. Serial data: ${JSON.stringify(disassembly.body.instructions)}`
    );
  }
  const file = readFile(repoDirFile("test/stackframes.cpp"));
  const bp_lines = ["BP1", "BP2", "BP3", "BP4"]
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }));
  if (bp_lines.length != 4)
    throw new Error(
      `Expected to find 4 breakpoint locations but found ${bp_lines.length}`
    );
  await da_client.sendReqGetResponse("setBreakpoints", {
    source: {
      name: repoDirFile("test/stackframes.cpp"),
      path: repoDirFile("test/stackframes.cpp"),
    },
    breakpoints: bp_lines,
  });
  const threads = await da_client.threads();
  await da_client
    .stackTrace(threads[0].id)
    .then(({ response_seq, command, type, success, body: { stackFrames } }) => {
      checkResponse({ type, success, command }, "stackTrace", true);
      if (stackFrames.length != 4)
        throw new Error(
          `We're exactly at the start of the first instruction of main - expecting only 1 frame but got ${stackFrames.length}: ${JSON.stringify(stackFrames)}`
        );
    });
  const total = 5;
  for (let i = total; i < 9; i++) {
    await da_client.sendReqWaitEvent(
      "continue",
      { threadId: threads[0].id },
      "stopped",
      seconds(1)
    );
    await da_client.stackTrace(threads[0].id).then((res) => {
      checkResponse(res, "stackTrace", true);
      const { stackFrames } = res.body;
      if (stackFrames.length != i) {
        throw new Error(
          `Expected ${i} stackframes but got ${stackFrames.length}: ${JSON.stringify(stackFrames, null, 2)}`
        );
      }

      for (const idx in stackFrames) {
        if (stackFrames[idx].line != expectedStackTraces[i - total][idx].line) {
          throw new Error(
            `Expected line to be at ${expectedStackTraces[i - total][idx].line
            } but was ${stackFrames[idx].line}: ${JSON.stringify(stackFrames, null, 2)}`
          );
        }
        if (stackFrames[idx].name != expectedStackTraces[i - total][idx].name) {
          throw new Error(
            `Expected name to be ${expectedStackTraces[i - total][idx].name
            } but was ${stackFrames[idx].name}: ${JSON.stringify(stackFrames, null, 2)}`
          );
        }
      }
    });
  }
}

const tests = {
  "insidePrologue": insidePrologueTest,
  "insideEpilogue": insideEpilogueTest,
  "normal": normalTest,
  "unwindFromSharedObject": unwindFromSharedObject
}

runTestSuite(tests);