const { DAClient, MDB_PATH, checkResponse, testException, getLineOf, readFile, buildDirFile, repoDirFile } = require("./client")

const da_client = new DAClient(MDB_PATH, []);

const expectedStackTraces = [
  [{ line: 39, name: "foo" }, { line: 46, name: "main" }, { line: 0, name: "unknown" }],
  [{ line: 33, name: "bar" }, { line: 40, name: "foo" }, { line: 46, name: "main" }, { line: 0, name: "unknown" }],
  [{ line: 14, name: "baz" }, { line: 34, name: "bar" }, { line: 40, name: "foo" }, { line: 46, name: "main" }, { line: 0, name: "unknown" }],
  [{ line: 7, name: "quux" }, { line: 16, name: "baz" }, { line: 34, name: "bar" }, { line: 40, name: "foo" }, { line: 46, name: "main" }, { line: 0, name: "unknown" }]
]

async function test() {

  await da_client.launchToMain(buildDirFile("stackframes"));
  const disassembly = await da_client.sendReqGetResponse("disassemble", { memoryReference: "0x401210", offset: 0, instructionOffset: 0, instructionCount: 9, resolveSymbols: false });
  if (disassembly.body.instructions.length != 9) {
    throw new Error(`Expected 4 disassembled instructions but instead got ${disassembly.body.instructions.length}. Serial data: ${JSON.stringify(disassembly.body.instructions)}`);
  }
  const file = readFile(repoDirFile("test/stackframes.cpp"));
  const bp_lines = ["BP1", "BP2", "BP3", "BP4"].map(ident => getLineOf(file, ident)).filter(item => item != null).map(l => ({ line: l }));
  if (bp_lines.length != 4) throw new Error(`Expected to find 4 breakpoint locations but found ${bp_lines.length}`);
  await da_client.sendReqGetResponse("setBreakpoints", {
    source: {
      name: repoDirFile("test/stackframes.cpp"),
      path: repoDirFile("test/stackframes.cpp"),
    },
    breakpoints: bp_lines
  }).catch(testException);
  const threads = await da_client.threads();
  await da_client.stackTrace(threads[0].id).then(({ response_seq, command, type, success, body: { stackFrames } }) => {
    checkResponse(__filename, { type, success, command }, "stackTrace", true);
    if (stackFrames.length > 1) throw new Error(`We're exactly at the start of the first instruction of main - expecting only 1 frame but got ${stackFrames.length}`);
  });

  for (let i = 3; i < 7; i++) {
    await da_client.contNextStop(threads[0].id);
    await da_client.stackTrace(threads[0].id).then(res => {
      checkResponse(__filename, res, "stackTrace", true);
      const { stackFrames } = res.body;
      if (stackFrames.length != i) {
        throw new Error(`Expected ${i} stackframes but got ${stackFrames.length}`);
      }

      for (const idx in stackFrames) {
        if (stackFrames[idx].line != expectedStackTraces[i - 3][idx].line) {
          throw new Error(`Expected line to be at ${expectedStackTraces[i - 3][idx].line} but was ${stackFrames[idx].line}`);
        }
        if (stackFrames[idx].name != expectedStackTraces[i - 3][idx].name) {
          throw new Error(`Expected name to be ${expectedStackTraces[i - 3][idx].name} but was ${stackFrames[idx].name}`);
        }
      }

    });
  }
}

test().then(() => {
  console.log(`Test ${__filename} succeeded`);
  process.exit(0);
}).catch(testException);