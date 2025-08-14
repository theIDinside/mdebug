const { readFileContents, repoDirFile, getLineOf, seconds, doSomethingDelayed } = require('./client')

/** @param {import("./client").DebugAdapterClient } debugAdapter */
async function pause(debugAdapter) {
  await debugAdapter.startRunToMain(debugAdapter.buildDirFile('pause'))
  const file = readFileContents(repoDirFile('test/pause.cpp'))
  const line_where_sleep_is_called = ['SLEEPLINE']
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))[0]

  const threads = await debugAdapter.threads()
  const threadId = threads[0].id
  console.log('CONASIDHASKDA')
  const continueRes = await debugAdapter.continueRequest({
    threadId: threadId,
    singleThread: false,
  })
  // wait a second. The sleep call we will be interrupting is sleeping for 15 seconds, so this is fine.
  await doSomethingDelayed(async () => {
    let hitMainStoppedPromise = debugAdapter.prepareWaitForEventN('stopped', 1, 1000, doSomethingDelayed)
    console.log('PAUSING')
    const pauseResponse = await debugAdapter.pauseRequest({ threadId: threadId })
    await hitMainStoppedPromise
    let frames = await debugAdapter.stackTrace(threads[0].id)
    console.log(`${JSON.stringify(frames, null, 2)}`)
  }, seconds(1))
}

const tests = {
  pause: () => pause,
}

module.exports = {
  tests: tests,
}
