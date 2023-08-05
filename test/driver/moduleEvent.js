const {
  DAClient,
  MDB_PATH,
  buildDirFile,
  runTest,
} = require("./client")(__filename);

const da_client = new DAClient(MDB_PATH, []);

const sharedObjectsCount = 6;

async function test() {
  let modules_event_promise = da_client.prepareWaitForEventN("module", 6, 2000);
  await da_client.launchToMain(buildDirFile("threads_shared"));
  const res = await modules_event_promise;

  if (res.length != sharedObjectsCount) {
    throw new Error(`Expected to see 6 module events for shared objects but saw ${res.length}`);
  }

}

runTest(test);
