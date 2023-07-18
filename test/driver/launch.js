const { DAClient, MDB_PATH, check_response } = require("./client")

const da_client = new DAClient(MDB_PATH, []);

async function test() {
  // we don't care for initialize, that's tested elsewhere
  await da_client.send_req_get_response("initialize", {}).then(res => {
    check_response(__filename, res, "initialize", true);
  })

  await da_client.send_req_get_response("launch", { program: "/home/cx/dev/foss/cx/dbm/build-debug/bin/stackframes", stopAtEntry: true }).then(response => {
    check_response(__filename, response, "launch", true);
    console.log(`Test ${__filename} succeeded`);
    process.exit(0);
  }).catch(err => {
    console.error(`Test failed: ${err}`);
    process.exit(-1);
  });

  process.on("exit", () => {
    da_client.mdb.kill();
  });
}

test();