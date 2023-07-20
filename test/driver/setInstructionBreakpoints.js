const { DAClient, MDB_PATH, checkResponse: check_response, testException, buildDirFile } = require("./client")

const da_client = new DAClient(MDB_PATH, []);

// we don't care for initialize, that's tested elsewhere
da_client.sendReqGetResponse("initialize", {}).then(res => {
  check_response(__filename, res, "initialize", true);
}).catch(testException)

da_client.sendReqGetResponse("launch", { program: buildDirFile("stackframes"), stopAtEntry: true }).then(res => {
  check_response(__filename, res, "launch", true);
  console.log(`launch was ok`);
}).catch(testException);

da_client.sendReqGetResponse("setInstructionBreakpoints", { breakpoints: [{ "instructionReference": "0x40127e" }] }).then(res => {
  console.log(`setIns bkpt request...`);
  check_response(__filename, res, "setInstructionBreakpoints", true);
  if (res.body.breakpoints.length != 1) {
    throw new Error(`Expected bkpts 1 but got ${res.body.breakpoints.length}`)
  }
  const { id, verified, instructionReference } = res.body.breakpoints[0];
  if (!verified) throw new Error("Expected breakpoint to be verified and exist!");
  if (instructionReference != "0x40127e") throw new Error(`Attempted to set ins breakpoint at 0x40127e but it was set at ${instructionReference}`);
  process.exit(0);
}).catch(testException)