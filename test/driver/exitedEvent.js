const { seconds } = require('./client')
const { assert, assertLog, prettyJson } = require('./utils')

async function programExit(DA) {
  await DA.startRunToMain(DA.buildDirFile('stackframes'))
  const threads = await DA.threads()
  const { event_body, response } = await DA.sendReqWaitEvent(
    'continue',
    { threadId: threads[0].id },
    'thread',
    seconds(2)
  )
  assert(
    event_body.reason == 'exited',
    `Expected an 'thread exit' event: ${prettyJson(event_body)} after response ${prettyJson(response)}`
  )
  assert(event_body.threadId == threads[0].id, `Expected to see ${threads[0].id} exit, but saw ${event_body.threadId}`)
}

/**
 * @param { import("./client").DebugAdapterClient } DA
 */
async function readExitCode(DA) {
  await DA.startRunToMain(DA.buildDirFile('stackframes'))
  const threads = await DA.getThreads()
  const { event_body } = await DA.sendReqWaitEvent('continue', { threadId: threads[0].id }, 'exited', seconds(1))
  const ExpectedExitCode = 241
  assertLog(
    event_body.exitCode == ExpectedExitCode,
    `Expected exitCode == ${ExpectedExitCode}`,
    ` Failed. Got ${prettyJson(event_body)}`
  )
}

const tests = {
  programExit: () => programExit,
  readExitCode: () => readExitCode,
}

module.exports = {
  tests: tests,
}
