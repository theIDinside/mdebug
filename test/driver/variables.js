const { DAClient, MDB_PATH, prettyJson, buildDirFile, getLineOf, readFile, repoDirFile, runTestSuite } =
  require('./client')(__filename)

function allUniqueVariableReferences(variables) {
  // yes I know this is slower. 2 iterations. 2 created arrays. bla bla.
  const idsOnly = []
  for (const v of variables) {
    if (v.variablesReference != 0) idsOnly.push(v.variablesReference)
  }
  return new Set(idsOnly).size == idsOnly.length
}

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

  // verify uniqueness of scope variable references
  if (!allUniqueVariableReferences(scopes))
    throw new Error(`Expected unique variableReference for all scopes. Scopes:\n${JSON.stringify(scopes, null, 2)}`)

  for (const scope of scopes) {
    if (scope.name == 'Arguments') {
      const vres = await da_client.sendReqGetResponse('variables', { variablesReference: scope.variablesReference })
      const variables = vres.body.variables
      if (!allUniqueVariableReferences(variables))
        throw new Error(
          `Duplicate variablesReferences found (that were non-zero).\nResponse:\n${JSON.stringify(variables, null, 2)}`
        )
      if (variables.length != 2)
        throw new Error(`Expected 2 variables but got ${variables.length}. Variables response: ${prettyJson(vres)}`)
      console.log(`${JSON.stringify(variables)}`)
      for (const v of variables) {
        if (v.name == 'name') {
          console.log(
            `We got the const char* argument passed to the fn. It's variables reference is: ${v.variablesReference}`
          )
        }
      }
    }

    if (scope.name == 'Locals') {
      const vres = await da_client.sendReqGetResponse('variables', { variablesReference: scope.variablesReference })
      const variables = vres.body.variables
      if (!allUniqueVariableReferences(variables))
        throw new Error(
          `Duplicate variablesReferences found (that were non-zero).\nResponse:\n${JSON.stringify(variables, null, 2)}`
        )
      if (variables.length != 6)
        throw new Error(
          `[varRef: ${scope.variablesReference}]: Expected 6 variables but got ${
            variables.length
          }. Variables response: ${prettyJson(vres)}`
        )
      for (const v of variables) {
        if (v.name == 'structure') {
          console.log(`[variables request]: varRef: ${v.variablesReference}, name='${v.name}'`)
          const vres = await da_client.sendReqGetResponse('variables', { variablesReference: v.variablesReference })
          const variables = vres.body.variables
          if (!allUniqueVariableReferences(variables))
            throw new Error(
              `Duplicate variablesReferences found (that were non-zero).\nResponse:\n${JSON.stringify(
                variables,
                null,
                2
              )}`
            )
          if (variables.length != 3)
            throw new Error(
              `[varRef: ${scope.variablesReference}]: Expected 3 member variables of '${v.name}' but got ${
                variables.length
              }. Variables response: ${prettyJson(vres)}`
            )
          console.log(`contents of struct Structured:\n${JSON.stringify(variables, null, 2)}`)
        }
      }
    }
  }
}

const tests = {
  baseTypes: baseTypes,
}

runTestSuite(tests)
