const { DAClient, MDB_PATH, check_response } = require("./client")

const da_client = new DAClient(MDB_PATH, []);

da_client.send_req_get_response("initialize", {}).then(response => {
  check_response(response, "initialize", true);
  console.log(`Test ${__filename} succeeded`);
  process.exit(0);
}).catch(err => {
  console.error(`Test failed: ${err}`);
});