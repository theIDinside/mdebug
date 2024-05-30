const { seconds } = require('./client')
const { assert, prettyJson } = require('./utils')

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

const tests = {
  programExit: () => programExit,
}

module.exports = {
  tests: tests,
}
