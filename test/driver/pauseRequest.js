const { readFileContents, repoDirFile, getLineOf, seconds, doSomethingDelayed } = require('./client')

/**
 * @param {import("./client").DAClient } debugAdapter
 */
async function pause(debugAdapter) {
  await debugAdapter.startRunToMain(debugAdapter.buildDirFile('pause'))
  const file = readFileContents(repoDirFile('test/pause.cpp'))
  const line_where_sleep_is_called = ['SLEEPLINE']
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))[0]

  const threads = await debugAdapter.threads()
  const threadId = threads[0].id
  const continue_res = await debugAdapter.sendReqGetResponse('continue', {
    threadId: threadId,
    singleThread: false,
  })
  // wait a second. The sleep call we will be interrupting is sleeping for 15 seconds, so this is fine.
  await doSomethingDelayed(async () => {
    let hit_main_stopped_promise = debugAdapter.prepareWaitForEventN('stopped', 1, 1000, doSomethingDelayed)
    const pauseResponse = await debugAdapter.sendReqGetResponse('pause', { threadId: threadId })
    await hit_main_stopped_promise
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
