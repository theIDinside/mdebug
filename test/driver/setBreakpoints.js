const {
  DAClient,
  MDB_PATH,
  buildDirFile,
  checkResponse,
  getLineOf,
  readFile,
  repoDirFile,
  runTestSuite,
} = require("./client")(__filename);

async function set4Breakpoints() {
  const da_client = new DAClient(MDB_PATH, []);
  // we don't care for initialize, that's tested elsewhere
  da_client
    .sendReqGetResponse("initialize", {})
    .then((res) => {
      checkResponse(__filename, res, "initialize", true);
    })
    .then(() => {
      return da_client
        .sendReqGetResponse("launch", {
          program: buildDirFile("stackframes"),
          stopAtEntry: true,
        })
        .then((res) => {
          checkResponse(res, "launch", true);
        })
    })
    .then(() => {
      const bpRequest = "setBreakpoints";
      const file = readFile(repoDirFile("test/stackframes.cpp"));
      const bp_lines = ["BP1", "BP2", "BP3", "BP4"]
        .map((ident) => getLineOf(file, ident))
        .filter((item) => item != null)
        .map((l) => ({ line: l }));
      da_client
        .sendReqGetResponse(bpRequest, {
          source: {
            name: repoDirFile("test/stackframes.cpp"),
            path: repoDirFile("test/stackframes.cpp"),
          },
          breakpoints: bp_lines,
        })
        .then((res) => {
          checkResponse(res, bpRequest, true);
          if (res.body.breakpoints.length != 4) {
            throw new Error(
              `Expected bkpts 3 but got ${res.body.breakpoints.length}`
            );
          }
          const found_all = [false, false, false];
          for (let i = 0; i < bp_lines.length; i++) {
            for (let bp of res.body.breakpoints) {
              if (bp.line == bp_lines[i].line) found_all[i] = true;
            }
          }
          if (found_all.some((v) => v == false)) {
            throw new Error(
              `Expected to get breakpoints for lines ${JSON.stringify(
                bp_lines
              )} but got ${JSON.stringify(res.body.breakpoints)}`
            );
          }
          console.log(`Test ${__filename} succeeded`);
          process.exit(0);
        })
    });
}

const tests = {
  "set4Breakpoints": set4Breakpoints,
}

runTestSuite(tests);
