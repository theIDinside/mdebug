const { readFile, repoDirFile, getLineOf, prettyJson } = require('./client')
const { todo, assert } = require('./utils')

async function finish(DA) {
  await DA.launchToMain(DA.buildDirFile('stackframes'))
  const file = readFile(repoDirFile('test/stackframes.cpp'))
  const bp_lines = ['BP3']
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))
  const res = await DA.sendReqGetResponse('setBreakpoints', {
    source: {
      name: repoDirFile('test/stackframes.cpp'),
      path: repoDirFile('test/stackframes.cpp'),
    },
    breakpoints: bp_lines,
  })
  const threads = await DA.threads()
  await DA.contNextStop(threads[0].id)

  let frames = await DA.stackTrace(threads[0].id)
  const next_up_frame = frames.body.stackFrames[1]
  const { event_body, response } = await DA.sendReqWaitEvent(
    'stepOut',
    {
      threadId: threads[0].id,
      singleThread: true,
      granularity: 'instruction',
    },
    'stopped',
    1000
  )

  console.log(
    `We're at ${JSON.stringify(frames.body.stackFrames[0], null, 2)}\n\n Expected to stop at ${JSON.stringify(
      next_up_frame,
      null,
      2
    )}`
  )

  assert(response.success, `Request was unsuccessful: ${JSON.stringify(response)}`)
  assert(
    event_body.reason == 'step',
    `Expected to see a 'stopped' event with 'step' as reason. Got event ${prettyJson(event_body)}`
  )

  frames = await DA.stackTrace(threads[0].id)
  console.log(`Stopped at ${JSON.stringify(frames.body.stackFrames[0], null, 2)}`)
  assert(
    frames.body.stackFrames[0].line == next_up_frame.line,
    `Expected to be at line ${next_up_frame.line} but was at ${frames.body.stackFrames[0].line}`
  )
}

const finishAbortedDueToBkpt = todo('finishAbortedDueToBkpt')

const tests = {
  finish: finish,
  finishAbortedDueToBkpt: finishAbortedDueToBkpt,
}

module.exports = {
  tests: tests,
}
