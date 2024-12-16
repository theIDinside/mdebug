const { launchToGetFramesAndScopes, readFileContents, repoDirFile, getLineOf, SetBreakpoints } = require('./client')
const { assert, assertLog, prettyJson } = require('./utils')
const sharedObjectsCount = 6

async function expect6NewModuleEvents(DA) {
  let modules_event_promise = DA.prepareWaitForEventN('module', 6, 2000)
  await DA.startRunToMain(DA.buildDirFile('threads_shared'))
  const res = await modules_event_promise
  assert(
    res.length >= sharedObjectsCount,
    `Expected to see at least ${sharedObjectsCount} module events for shared objects but saw ${res.length}`
  )
}

async function assert1Pending(debugAdapter) {
  const dynamic_so_file = 'test/dynamic_lib.cpp'
  const file = readFileContents(repoDirFile(dynamic_so_file))
  const bpIdentifiers = ['BPMI']
  const bp_lines = bpIdentifiers
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))
  assertLog(bp_lines.length == bpIdentifiers.length, `Check that identifiers exist: ${bpIdentifiers}`)
  const args = {
    source: {
      name: repoDirFile(dynamic_so_file),
      path: repoDirFile(dynamic_so_file),
    },
    breakpoints: bp_lines,
  }
  const bkpt_res = await debugAdapter.sendReqGetResponse('setBreakpoints', args)
  assertLog(
    bkpt_res.body.breakpoints.length == 1,
    `Expected to find 1 identifier`,
    () => `Instead found ${prettyJson(bkpt_res)}`
  )
  const bp = bkpt_res.body.breakpoints[0]
  assertLog(!bp.verified, `Expected breakpoint to not be verified`)
  return bp
}

async function seeModuleEventFromDLOpenCall(debugAdapter) {
  let { threads, frames, scopes, bpres } = await launchToGetFramesAndScopes(
    debugAdapter,
    'test/dynamicLoading.cpp',
    ['BP_PRE_OPEN', 'BP_PRE_DLSYM', 'BP_PRE_CALL', 'BP_PRE_CLOSE'],
    'perform_dynamic',
    'dynamicLoading'
  )
  const dyn_bps = await SetBreakpoints(debugAdapter, 'test/dynamic_lib.cpp', ['BPMI'])
  const bp = await assert1Pending(debugAdapter)
  let breakpoint_events = debugAdapter.prepareWaitForEventN('breakpoint', 2, 1500)
  const template_path = repoDirFile('test/templated_code/template.h')
  const template_line = getLineOf(readFileContents(template_path), 'BP1')
  let bp_args = { source: { name: template_path, path: template_path }, breakpoints: [{ line: template_line }] }
  const templateBpRes = await debugAdapter.sendReqGetResponse('setBreakpoints', bp_args)
  assertLog(
    templateBpRes.body.breakpoints.length == 1,
    `Expected 1 breakpoint`,
    `Bp Args: ${prettyJson(bp_args)}.\n Response ${prettyJson(templateBpRes)}`
  )

  console.log(`breakpoints: ${prettyJson(templateBpRes.body.breakpoints)}`);

  await debugAdapter.contNextStop(threads[0].id)
  const res = await breakpoint_events
  assertLog(
    res.length == 2,
    `Expected to see 2 new breakpoint event due to dlopen call`,
    () => `But saw ${res.length}: ${prettyJson(res)}`
  )
  let changed_seen = false
  let new_seen = false
  for (const evt of res) {
    assertLog(
      evt.breakpoint.verified,
      `Expected breakpoint to be verified`,
      `But wasn't: ${prettyJson(evt.breakpoint)}`
    )
    switch (evt.reason) {
      case 'changed':
        changed_seen = true
        assertLog(
          evt.breakpoint.source.name.includes('dynamic_lib.cpp'),
          () => `Expected to see breakpoint changed for source file 'dynamic_lib.cpp'`,
          `But saw instead ${prettyJson(evt.breakpoint)}`
        )
        break
      case 'new':
        {
          new_seen = true
          assertLog(
            evt.breakpoint.source.name.includes('template.h'),
            `Expected to see breakpoint changed for source file 'template.h'`,
            () => `Change was instead for ${prettyJson(evt.breakpoint)}`
          )
        }
        break
    }
  }

  assertLog(changed_seen, "Expected to see 'changed' breakpoint event")
  assertLog(new_seen, "Expected to see 'new' breakpoint event")
  const new_bp = res[0].breakpoint
  assertLog(
    bp.id == new_bp.id,
    `Expected breakpoint id ${bp.id} to have changed`,
    `Changed ID was instead ${new_bp.id}`
  )
}

async function newFunctionBreakpointAfterLoadedSharedObject(debugAdapter) {
  let { threads, frames, scopes } = await launchToGetFramesAndScopes(
    debugAdapter,
    'test/dynamicLoading.cpp',
    ['BP_PRE_OPEN', 'BP_PRE_DLSYM', 'BP_PRE_CALL', 'BP_PRE_CLOSE'],
    'perform_dynamic',
    'dynamicLoading'
  )

  let breakpoint_events = debugAdapter.prepareWaitForEventN('breakpoint', 1, 5000)
  const fnBreakpointResponse = await debugAdapter.sendReqGetResponse('setFunctionBreakpoints', {
    breakpoints: [{ name: 'less_than<\\w+>', regex: true }],
  })
  await debugAdapter.contNextStop(threads[0].id)
  const res = await breakpoint_events
  const bp = res[0].breakpoint
  assertLog(bp.verified, 'Expected breakpoint to be verified', `Breakpoint: ${JSON.stringify(res)}`)
  assertLog(bp.line == 9, 'Expected to see a new breakpoint at line 9', `Breakpoint: ${JSON.stringify(res)}`)
  assertLog(
    bp.source.name.includes('template.h'),
    "Expected file to be 'template.h'",
    `Breakpoint: ${JSON.stringify(res)}`
  )

  console.log(prettyJson(res))
}

const tests = {
  '6modules': () => expect6NewModuleEvents,
  DLOpen: () => seeModuleEventFromDLOpenCall,
  newFunctionBreakpointAfterLoadedSharedObject: () => newFunctionBreakpointAfterLoadedSharedObject,
}

module.exports = {
  tests: tests,
}
