const {
  DAClient,
  MDB_PATH,
  check_response,
  testException,
} = require("./client");

const da_client = new DAClient(MDB_PATH, []);

const verify_breakpoints = [{ line: 7 }, { line: 13 }, { line: 45 }]

// we don't care for initialize, that's tested elsewhere
da_client
  .send_req_get_response("initialize", {})
  .then((res) => {
    check_response(__filename, res, "initialize", true);
  })
  .catch(testException)
  .then(() => {
    return da_client
      .send_req_get_response("launch", {
        program: "/home/cx/dev/foss/cx/dbm/build-debug/bin/stackframes",
        stopAtEntry: true,
      })
      .then((res) => {
        check_response(__filename, res, "launch", true);
        console.log(`launch was ok`);
      })
      .catch(testException);
  }).then(() => {
    const bpRequest = "setBreakpoints"
    da_client
      .send_req_get_response(bpRequest, {
        source: {
          name: "/home/cx/dev/foss/cx/dbm/test/stackframes.cpp",
          path: "/home/cx/dev/foss/cx/dbm/test/stackframes.cpp",
        },
        breakpoints: verify_breakpoints,
      })
      .then((res) => {
        check_response(__filename, res, bpRequest, true);
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
