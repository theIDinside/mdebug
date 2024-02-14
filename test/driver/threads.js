const { getLineOf, readFile, repoDirFile, prettyJson } = require('./client')
const { assert } = require('./utils')

async function threads(DA) {
  await DA.launchToMain(DA.buildDirFile('threads_shared'))
  let threads = await DA.threads()
  const file = readFile(repoDirFile('test/threads_shared.cpp'))
  const bp_lines = ['BP1']
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))
  await DA.sendReqGetResponse('setBreakpoints', {
    source: {
      name: repoDirFile('test/threads_shared.cpp'),
      path: repoDirFile('test/threads_shared.cpp'),
    },
    breakpoints: bp_lines,
  })

  await DA.contNextStop(threads[0].id)
  threads = await DA.threads()
  let frames = await DA.stackTrace(threads[1].id, 1000)
  console.log(`next line for ${threads[1].id}: (${JSON.stringify(threads[1], null, 2)})`)
  const { event_body, response } = await DA.sendReqWaitEvent(
    'next',
    {
      threadId: threads[1].id,
      singleThread: true,
      granularity: 'line',
    },
    'stopped',
    500
  )

  assert(response.success, `Expected 'next' command to succeed; got ${JSON.stringify(response)}`)

  frames = await DA.stackTrace(threads[1].id)
  console.log(`Stack frames for ${threads[1].id}: ${JSON.stringify(frames, null, 2)}`)
  const end_line = frames.body.stackFrames[0].line
  assert(
    end_line == bp_lines[0].line + 1,
    `Expected to be at line ${bp_lines[0].line + 1} but we're at line ${end_line}: ${prettyJson(
      frames.body.stackFrames
    )}`
  )
}
const tests = {
  threads: threads,
}

module.exports = {
  tests: tests,
}
