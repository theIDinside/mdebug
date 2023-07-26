const {
  DAClient,
  MDB_PATH,
  buildDirFile,
  runTest,
  seconds,
} = require("./client")(__filename);

const da_client = new DAClient(MDB_PATH, []);

async function test() {
  await da_client.launchToMain(buildDirFile("stackframes"));
  const threads = await da_client.threads();
  const evt = await da_client.sendReqWaitEvent(
    "continue",
    { threadId: threads[0].id },
    "thread",
    seconds(2)
  );
  if (evt.reason != "exited")
    throw new Error("Expected an 'thread exit' event");
  if (evt.threadId != threads[0].id)
    throw new Error(
      `Expected to see ${threads[0].id} exit, but saw ${evt.threadId}`
    );
}

runTest(test);
