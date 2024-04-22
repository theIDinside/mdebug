const { launchToGetFramesAndScopes, readFileContents, repoDirFile, getLineOf } = require('./client')
const { assert, prettyJson } = require('./utils')
const sharedObjectsCount = 6

async function expect6NewModuleEvents(DA) {
  let modules_event_promise = DA.prepareWaitForEventN('module', 6, 2000)
  await DA.launchToMain(DA.buildDirFile('threads_shared'))
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
  assert(bp_lines.length == bpIdentifiers.length, `Could not find these identifiers: ${bpIdentifiers}`)
  const args = {
    source: {
      name: repoDirFile(dynamic_so_file),
      path: repoDirFile(dynamic_so_file),
    },
    breakpoints: bp_lines,
  }
  const bkpt_res = await debugAdapter.sendReqGetResponse('setBreakpoints', args)
  assert(
    bkpt_res.body.breakpoints.length == 1,
    () => `Could not find these identifiers: ${bpIdentifiers}: ${prettyJson(bkpt_res)}`
  )
  const bp = bkpt_res.body.breakpoints[0]
  assert(!bp.verified, `Expected breakpoint to not be verified`)
  return bp
}

async function seeModuleEventFromDLOpenCall(debugAdapter) {
  let { threads, frames, scopes } = await launchToGetFramesAndScopes(
    debugAdapter,
    'test/dynamicLoading.cpp',
    ['BP_PRE_OPEN', 'BP_PRE_DLSYM', 'BP_PRE_CALL', 'BP_PRE_CLOSE'],
    'perform_dynamic',
    'dynamicLoading'
  )

  const bp = await assert1Pending(debugAdapter)
  let breakpoint_events = debugAdapter.prepareWaitForEventN('breakpoint', 1, 2000)
  const template_path = repoDirFile('test/templated_code/template.h')
  const template_line = getLineOf(readFileContents(template_path), 'BP1')
  let bp_args = { source: { name: template_path, path: template_path }, breakpoints: [{ line: template_line }] }
  const templateBpRes = await debugAdapter.sendReqGetResponse('setBreakpoints', bp_args)
  assert(
    templateBpRes.body.breakpoints.length == 1,
    `Expected 1 breakpoint using ${prettyJson(bp_args)} but got ${prettyJson(templateBpRes)}`
  )

  await debugAdapter.contNextStop(threads[0].id)
  const res = await breakpoint_events
  assert(
    res.length == 2,
    () => `Expected to see 2 new breakpoint event due to dlopen call but saw ${res.length}: ${prettyJson(res)}`
  )
  let obj = { changed_seen: false, new_seen: false }
  for (const evt of res) {
    assert(evt.breakpoint.verified, `Expected breakpoint to be verified but wasn't: ${prettyJson(evt.breakpoint)}`)
    switch (evt.reason) {
      case 'changed':
        changed_seen = true
        assert(
          evt.breakpoint.source.name.includes('dynamic_lib.cpp'),
          () =>
            `Expected to see breakpoint changed for source file 'dynamic_lib.cpp' but saw instead ${prettyJson(
              evt.breakpoint
            )}`
        )
        break
      case 'new':
        {
          new_seen = true
          assert(
            evt.breakpoint.source.name.includes('template.h'),
            () =>
              `Expected to see breakpoint changed for source file 'template.h' but saw instead ${prettyJson(
                evt.breakpoint
              )}`
          )
        }
        break
    }
  }

  assert(changed_seen, "Expected to see 'changed' breakpoint event")
  assert(new_seen, "Expected to see 'new' breakpoint event")
  console.log(prettyJson(res))
  const new_bp = res[0].breakpoint
  assert(bp.id == new_bp.id, `Expected breakpoint id ${bp.id} to have changed but was ${new_bp.id}`)
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
  assert(bp.verified, 'Expected breakpoint to be verified')
  assert(bp.line == 9, 'Expected to see a new breakpoint at line 9')
  assert(bp.source.name.includes('template.h'), "Expected file to be 'template.h'")

  console.log(prettyJson(res))
}

const tests = {
  '6modules': expect6NewModuleEvents,
  DLOpen: seeModuleEventFromDLOpenCall,
  newFunctionBreakpointAfterLoadedSharedObject: newFunctionBreakpointAfterLoadedSharedObject,
}

module.exports = {
  tests: tests,
}
