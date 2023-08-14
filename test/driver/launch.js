const {
  DAClient,
  MDB_PATH,
  buildDirFile,
  checkResponse,
  runTestSuite,
} = require("./client")(__filename);

async function launch() {
  const da_client = new DAClient(MDB_PATH, []);
  // we don't care for initialize, that's tested elsewhere
  await da_client
    .sendReqGetResponse("initialize", {}, 1000)
    .then((res) => checkResponse(res, "initialize", true));
  await da_client
    .sendReqGetResponse("launch", {
      program: buildDirFile("stackframes"),
      stopAtEntry: true,
    })
    .then((res) => checkResponse(res, "launch", true));
}

const tests = {
  "launch": launch
}

runTestSuite(tests);
