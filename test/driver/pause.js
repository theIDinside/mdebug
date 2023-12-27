const {
  DAClient,
  MDB_PATH,
  buildDirFile,
  runTestSuite,
  readFile,
  repoDirFile,
  getLineOf,
  seconds,
  doSomethingDelayed,
} = require('./client')(__filename)

async function pause() {
  const da_client = new DAClient(MDB_PATH, [])
  await da_client.launchToMain(buildDirFile('pause'))
  const file = readFile(repoDirFile('test/pause.cpp'))
  const line_where_sleep_is_called = ['SLEEPLINE']
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))[0]

  const threads = await da_client.threads()
  const threadId = threads[0].id
  const continue_res = await da_client.sendReqGetResponse('continue', {
    threadId: threadId,
    singleThread: false,
  })
  // wait a second. The sleep call we will be interrupting is sleeping for 15 seconds, so this is fine.
  await doSomethingDelayed(async () => {
    const pauseResponse = await da_client.sendReqGetResponse('pause', { threadId: threadId })
    let frames = await da_client.stackTrace(threads[0].id)
    console.log(`${JSON.stringify(frames, null, 2)}`)
  }, seconds(1))
}

const tests = {
  pause: pause,
}

runTestSuite(tests).then(() => {
  console.log(`done with test`)
})
