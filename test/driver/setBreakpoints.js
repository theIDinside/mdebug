const {
  DAClient,
  MDB_PATH,
  checkResponse,
  buildDirFile,
  testException,
  repoDirFile,
} = require("./client");

const da_client = new DAClient(MDB_PATH, []);

const verify_breakpoints = [{ line: 7 }, { line: 13 }, { line: 45 }]

// we don't care for initialize, that's tested elsewhere
da_client
  .sendReqGetResponse("initialize", {})
  .then((res) => {
    checkResponse(__filename, res, "initialize", true);
  })
  .catch(testException)
  .then(() => {
    return da_client
      .sendReqGetResponse("launch", {
        program: buildDirFile("stackframes"),
        stopAtEntry: true,
      })
      .then((res) => {
        checkResponse(__filename, res, "launch", true);
        console.log(`launch was ok`);
      })
      .catch(testException);
  }).then(() => {
    const bpRequest = "setBreakpoints"
    da_client
      .sendReqGetResponse(bpRequest, {
        source: {
          name: repoDirFile("test/stackframes.cpp"),
          path: repoDirFile("test/stackframes.cpp"),
        },
        breakpoints: verify_breakpoints,
      })
      .then((res) => {
        checkResponse(__filename, res, bpRequest, true);
        if (res.body.breakpoints.length != 3) {
          throw new Error(
            `Expected bkpts 3 but got ${res.body.breakpoints.length}`
          );
        }
        const found_all = [false, false, false];
        for (let i = 0; i < verify_breakpoints.length; i++) {
          for (let bp of res.body.breakpoints) {
            if (bp.line == verify_breakpoints[i].line) found_all[i] = true;
          }
        }
        if (found_all.some(v => v == false)) {
          throw new Error(`Expected to get breakpoints for lines ${JSON.stringify(verify_breakpoints)} but got ${JSON.stringify(res.body.breakpoints)}`);
        }
        console.log(`Test ${__filename} succeeded`);
        process.exit(0);
      })
      .catch(testException);
  })
