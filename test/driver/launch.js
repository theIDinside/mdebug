const { DAClient, MDB_PATH, checkResponse: check_response } = require("./client")

const da_client = new DAClient(MDB_PATH, []);

// we don't care for initialize, that's tested elsewhere
da_client.sendReqGetResponse("initialize", {}).then(res => {
  check_response(__filename, res, "initialize", true);
})

da_client.sendReqGetResponse("launch", { program: "/home/cx/dev/foss/cx/dbm/build-debug/bin/stackframes", stopAtEntry: true }).then(response => {
  check_response(__filename, response, "launch", true);
  console.log(`Test ${__filename} succeeded`);
  process.exit(0);
}).catch(err => {
  console.error(`Test failed: ${err}`);
  process.exit(-1);
});