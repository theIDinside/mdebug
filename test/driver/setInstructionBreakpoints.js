const { DAClient, MDB_PATH, buildDirFile, checkResponse, runTest } =
  require("./client")(__filename);

const da_client = new DAClient(MDB_PATH, []);

async function test() {
  // we don't care for initialize, that's tested elsewhere
  await da_client
    .sendReqGetResponse("initialize", {})
    .then((res) => checkResponse(res, "initialize", true));
  await da_client
    .sendReqGetResponse("launch", {
      program: buildDirFile("stackframes"),
      stopAtEntry: true,
    })
    .then((res) => checkResponse(res, "launch", true));

  await da_client
    .sendReqGetResponse("setInstructionBreakpoints", {
      breakpoints: [{ instructionReference: "0x40127e" }],
    })
    .then((res) => {
      checkResponse(res, "setInstructionBreakpoints", true);
      if (res.body.breakpoints.length != 1) {
        throw new Error(
          `Expected bkpts 1 but got ${res.body.breakpoints.length}`
        );
      }
      const { id, verified, instructionReference } = res.body.breakpoints[0];
      if (!verified)
        throw new Error("Expected breakpoint to be verified and exist!");
      if (instructionReference != "0x40127e")
        throw new Error(
          `Attempted to set ins breakpoint at 0x40127e but it was set at ${instructionReference}`
        );
    });
}

runTest(test);
