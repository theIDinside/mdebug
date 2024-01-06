const { DAClient, MDB_PATH, prettyJson, buildDirFile, getLineOf, readFile, repoDirFile, runTestSuite } =
  require('./client')(__filename)

async function baseTypes() {
  const MAIN_FILE = 'test/basetypes.cpp'
  const da_client = new DAClient(MDB_PATH, [])
  await da_client.launchToMain(buildDirFile('basetypes'))
  const file = readFile(repoDirFile(MAIN_FILE))
  const bp_lines = ['LEX_BLOCK', 'LOC_BP', 'ARGS_BP', 'STRUCT_BP', 'BYVAL_BP']
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))
  if (bp_lines.length != 5) throw new Error(`Expected to find 4 breakpoint locations but found ${bp_lines.length}`)
  await da_client.sendReqGetResponse('setBreakpoints', {
    source: {
      name: repoDirFile(MAIN_FILE),
      path: repoDirFile(MAIN_FILE),
    },
    breakpoints: bp_lines,
  })
  const threads = await da_client.threads()
  {
    await da_client.contNextStop(threads[0].id)
  }
  const fres = await da_client.stackTrace(threads[0].id, 1000)
  const frames = fres.body.stackFrames
  console.log(prettyJson(frames))
  if (frames[0].name != 'lexical_block')
    throw new Error(`Expected to be be in 'lexical_block' frame but was at ${frames[0].name}`)
  const scopes_res = await da_client.sendReqGetResponse('scopes', { frameId: frames[0].id })
  const scopes = scopes_res.body.scopes
  if (scopes.length != 3)
    throw new Error(`expected 3 scopes but got ${scopes.length}. Scopes response: ${prettyJson(scopes_res)}`)
  for (const scope of scopes) {
    if (scope.name == 'Arguments') {
      const vres = await da_client.sendReqGetResponse('variables', { variablesReference: scope.variablesReference })
      const variables = vres.body.variables
      if (variables.length == 5)
        throw new Error(`Expected 5 variables but got ${variables.length}. Variables response: ${prettyJson(vres)}`)
    }
  }
}

const tests = {
  baseTypes: baseTypes,
}

runTestSuite(tests)
