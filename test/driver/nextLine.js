const { readFile, repoDirFile, getLineOf, prettyJson } = require('./client')
const { todo, assert } = require('./utils')

function getLinesOf(names) {
  const file = readFile(repoDirFile('test/next.cpp'))
  return names
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))
}

async function setup(DA, bps) {
  await DA.launchToMain(DA.buildDirFile('next'))
  const file = readFile(repoDirFile('test/next.cpp'))
  const bp_lines = bps
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))

  assert(
    bp_lines.length == bps.length,
    `Could not parse contents of ${repoDirFile('test/next.cpp')} to find all string identifiers`
  )

  const breakpoint_response = await DA.sendReqGetResponse('setBreakpoints', {
    source: {
      name: repoDirFile('test/next.cpp'),
      path: repoDirFile('test/next.cpp'),
    },
    breakpoints: bp_lines,
  })
  assert(
    breakpoint_response.body.breakpoints.length == bps.length,
    `Expected to have set ${bps.length} breakpoints but only successfully set ${
      breakpoint_response.body.breakpoints.length
    }:\n${prettyJson(breakpoint_response)}`
  )
}

async function nextLineOverFunction(DA) {
  const bp_lines = getLinesOf(['BP1', 'BP2'])
  await setup(DA, ['BP1'])
  const threads = await DA.threads()
  await DA.contNextStop(threads[0].id)
  let frames = await DA.stackTrace(threads[0].id)
  const start_line = frames.body.stackFrames[0].line
  assert(
    start_line == bp_lines[0].line,
    `Expected to be on line ${bp_lines[0].line} for breakpoint but saw ${start_line}. Frames: ${prettyJson(frames)}`
  )

  const allThreadsStop = true
  const { event_body, response } = await DA.sendReqWaitEvent(
    'next',
    {
      threadId: threads[0].id,
      singleThread: !allThreadsStop,
      granularity: 'line',
    },
    'stopped',
    1000
  )

  assert(
    event_body.reason == 'step',
    `Expected to see a 'stopped' event with 'step' as reason. Got event ${prettyJson(event_body)}`
  )

  {
    frames = await DA.stackTrace(threads[0].id)
    const end_line = frames.body.stackFrames[0].line
    assert(
      end_line == bp_lines[1].line,
      `Expected to be at line ${bp_lines[1].line} but we're at line ${end_line}: ${prettyJson(frames.body.stackFrames)}`
    )
    console.log(`at correct line ${end_line}`)
  }
}

async function stopBecauseBpWhenNextLine(DA) {
  const bp_lines = getLinesOf(['BP1', 'BP3'])
  await setup(DA, ['BP1', 'BP3'])
  const threads = await DA.threads()
  let stopped = await DA.contNextStop(threads[0].id)
  let frames = await DA.stackTrace(threads[0].id)
  const start_line = frames.body.stackFrames[0].line
  assert(
    start_line == bp_lines[0].line,
    `Expected to be on line ${bp_lines[0].line} for breakpoint but saw ${start_line}`
  )
  const allThreadsStop = true
  const { event_body, response } = await DA.sendReqWaitEvent(
    'next',
    {
      threadId: threads[0].id,
      singleThread: !allThreadsStop,
      granularity: 'line',
    },
    'stopped',
    1000
  )
  assert(
    event_body.reason == 'breakpoint',
    `Expected to see a 'stopped' event with 'breakpoint' as reason. Got event ${JSON.stringify(event_body)}`
  )

  {
    frames = await DA.stackTrace(threads[0].id)
    const end_line = frames.body.stackFrames[0].line
    assert(
      end_line == bp_lines[1].line,
      `Expected to be at line ${bp_lines[1].line} but we're at line ${end_line}: ${prettyJson(frames.body.stackFrames)}`
    )
    console.log(`at correct line ${end_line}`)
  }
}

const nextLineInTemplateCode = todo('nextLineInTemplateCode')
const nextInstruction = todo('nextInstruction')

const tests = {
  nextLineOverFunction: nextLineOverFunction,
  stopBecauseBpWhenNextLine: stopBecauseBpWhenNextLine,
  nextLineInTemplateCode: nextLineInTemplateCode,
  nextInstruction: nextInstruction,
}

module.exports = {
  tests: tests,
}
