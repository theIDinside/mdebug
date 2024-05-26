const { readFileContents, repoDirFile, getLineOf, seconds, doSomethingDelayed } = require('./client')

async function pause(DA) {
  await DA.launchToMain(DA.buildDirFile('pause'))
  const file = readFileContents(repoDirFile('test/pause.cpp'))
  const line_where_sleep_is_called = ['SLEEPLINE']
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))[0]

  const threads = await DA.threads()
  const threadId = threads[0].id
  const continue_res = await DA.sendReqGetResponse('continue', {
    threadId: threadId,
    singleThread: false,
  })
  // wait a second. The sleep call we will be interrupting is sleeping for 15 seconds, so this is fine.
  await doSomethingDelayed(async () => {
    const pauseResponse = await DA.sendReqGetResponse('pause', { threadId: threadId })
    let frames = await DA.stackTrace(threads[0].id)
    console.log(`${JSON.stringify(frames, null, 2)}`)
  }, seconds(1))
}

const tests = {
  pause: () => pause,
}

module.exports = {
  tests: tests,
}
