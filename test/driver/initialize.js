const { DAClient, MDB_PATH, checkResponse, runTest } =
  require("./client")(__filename);

const da_client = new DAClient(MDB_PATH, []);

async function test() {
  await da_client
    .sendReqGetResponse("initialize", {}, 1000)
    .then((res) => checkResponse(res, "initialize", true));
}

runTest(test);
