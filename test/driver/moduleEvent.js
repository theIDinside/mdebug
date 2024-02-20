const { assert } = require('./utils')
const sharedObjectsCount = 6

async function test(DA) {
  let modules_event_promise = DA.prepareWaitForEventN('module', 6, 2000)
  await DA.launchToMain(DA.buildDirFile('threads_shared'))
  const res = await modules_event_promise
  assert(
    res.length >= sharedObjectsCount,
    `Expected to see at least ${sharedObjectsCount} module events for shared objects but saw ${res.length}`
  )
}

const tests = {
  '6modules': test,
}

module.exports = {
  tests: tests,
}
