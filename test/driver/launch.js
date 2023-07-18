const { DAClient, MDB_PATH, check_response } = require("./client")

const da_client = new DAClient(MDB_PATH, []);

// we don't care for initialize, that's tested elsewhere
da_client.send_req_get_response("initialize", {}).then(res => {
  check_response(res, "initialize", true);
  console.log("INIT SUCCESS");
})

da_client.send_req_get_response("launch", { program: "/home/cx/dev/foss/cx/dbm/build-debug/bin/stackframes", stopAtEntry: true }).then(response => {
  check_response(response, "launch", true);
  console.log(`Test ${__filename} succeeded`);
  process.exit(0);
}).catch(err => {
  console.error(`Test failed: ${err}`);
  process.exit(-1);
});

setTimeout(() => {
  console.log("done");
}, 1000);