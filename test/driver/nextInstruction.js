const { getStackFramePc, prettyJson } = require('./client')
const { assert } = require('./utils')

async function test(DA) {
  await DA.launchToMain(DA.buildDirFile('stackframes'))
  const threads = await DA.threads()
  let frames = await DA.stackTrace(threads[0].id)
  // await da_client.setInsBreakpoint("0x40121f");
  const pc = getStackFramePc(frames, 0)
  const disassembly = await DA.sendReqGetResponse('disassemble', {
    memoryReference: pc,
    offset: 0,
    instructionOffset: 0,
    instructionCount: 10,
    resolveSymbols: false,
  })
  const allThreadsStop = true
  // await da_client.contNextStop(threads[0].id);
  const { event_body, response } = await DA.sendReqWaitEvent(
    'next',
    {
      threadId: threads[0].id,
      singleThread: !allThreadsStop,
      granularity: 'instruction',
    },
    'stopped',
    1000
  )
  assert(response.success, `Request was unsuccessful: ${prettyJson(response)}`)
  assert(
    event_body.reason == 'step',
    `Expected to see a 'stopped' event with 'step' as reason. Got event ${prettyJson(event_body)}`
  )

  frames = await DA.stackTrace(threads[0].id)
  const next_pc = getStackFramePc(frames, 0)
  assert(
    next_pc == disassembly.body.instructions[1].address,
    `Expected to be at ${disassembly.body.instructions[1].address} but RIP=${next_pc} (previous pc: ${pc})`
  )
}

const tests = {
  oneInstruction: test,
}

module.exports = {
  tests: tests,
}
