const { DAClient, MDB_PATH, checkResponse: check_response } = require("./client")

const da_client = new DAClient(MDB_PATH, []);

da_client.sendReqGetResponse("initialize", {}).then(response => {
  check_response(__filename, response, "initialize", true);
  console.log(`Test ${__filename} succeeded`);
  process.exit(0);
}).catch(err => {
  console.error(`Test failed: ${err}`);
});