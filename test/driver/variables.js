const { DAClient, MDB_PATH, prettyJson, buildDirFile, getLineOf, readFile, repoDirFile, runTestSuite, assertEqAInB } =
  require('./client')(__filename)

const assert = require('assert')

/**
 * Verify that all objects in `varRefs` have unique variablesReference value.
 */
function assertAllVariableReferencesUnique(varRefs) {
  if (!allUniqueVariableReferences(varRefs))
    throw new Error(
      `Duplicate variablesReferences found (that were non-zero).\nResponse:\n${JSON.stringify(varRefs, null, 2)}`
    )
}

function allUniqueVariableReferences(variables) {
  // yes I know this is slower. 2 iterations. 2 created arrays. bla bla.
  const idsOnly = []
  for (const v of variables) {
    if (v.variablesReference != 0) idsOnly.push(v.variablesReference)
  }
  return new Set(idsOnly).size == idsOnly.length
}

/**
 * Verify that `vars` is of length `expectedCount`. `varRef` is
 * the variablesReference we requested `vars` for. `response` was the full response
 */
function assertVarResponseLength(vars, expectedCount, varRef, response) {
  if (vars.length != expectedCount)
    throw new Error(
      `[varRef: ${varRef}]: Expected ${expectedCount} variables but got ${
        vars.length
      }. Variables response: ${prettyJson(response)}`
    )
}

async function SetBreakpoints(debugAdapter, filePath, bpIdentifiers) {
  const file = readFile(repoDirFile(filePath))
  const bp_lines = bpIdentifiers
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))
  if (bp_lines.length != bpIdentifiers.length) {
    throw new Error(`Could not find these identifiers: ${bpIdentifiers}`)
  }
  const bkpt_res = await debugAdapter.sendReqGetResponse('setBreakpoints', {
    source: {
      name: repoDirFile(filePath),
      path: repoDirFile(filePath),
    },
    breakpoints: bp_lines,
  })
  if (bkpt_res.body.breakpoints.length != bpIdentifiers.length) {
    throw new Error(
      `Failed to set ${bpIdentifiers.length} breakpoints. Response: \n${JSON.stringify(bkpt_res, null, 2)}`
    )
  }
  return bp_lines
}

/**
 * Launch tracee to main, then set breakpoints at lines where `bpIdentifiers` can be found, issue a `threads` request
 * and issue 1 `continue` request stopping at first breakpoint. Issue a `stackTrace` request and a follow that
 * with a `scopes` request for the first frame in the stack trace.
 *
 * Returns the threads, stacktrace and the scopes of the newest frame
 * @param { DAClient } debugAdapter
 * @param { string } filePath - path to .cpp file that we are testing against
 * @param { string[] } bpIdentifiers - list of string identifiers that can be found in the .cpp file, where we set breakpoints
 * @param { string } expectedFrameName - frame name we expect to see on first stop.
 * @returns { { object[], object[], object[] } }
 */
async function launchToGetFramesAndScopes(
  debugAdapter,
  filePath,
  bpIdentifiers,
  expectedFrameName,
  exeFile = 'basetypes'
) {
  await debugAdapter.launchToMain(buildDirFile(exeFile), 5000)
  await SetBreakpoints(debugAdapter, filePath, bpIdentifiers)
  const threads = await debugAdapter.threads()
  await debugAdapter.contNextStop(threads[0].id)
  const fres = await debugAdapter.stackTrace(threads[0].id, 1000)
  const frames = fres.body.stackFrames
  if (frames[0].name != expectedFrameName) {
    throw new Error(
      `Expected to be inside of frame '${expectedFrameName}'. Actual: ${frames[0].name}. Stacktrace:\n${prettyJson(
        frames
      )}`
    )
  }

  const scopes_res = await debugAdapter.sendReqGetResponse('scopes', { frameId: frames[0].id })
  const scopes = scopes_res.body.scopes
  if (scopes.length != 3)
    throw new Error(`expected 3 scopes but got ${scopes.length}. Scopes response: ${prettyJson(scopes_res)}`)
  if (!allUniqueVariableReferences(scopes))
    throw new Error(`Expected unique variableReference for all scopes. Scopes:\n${JSON.stringify(scopes, null, 2)}`)

  return { threads, frames, scopes }
}

async function inConstructor() {
  const debugAdapter = new DAClient(MDB_PATH, [])
  let { threads, frames, scopes } = await launchToGetFramesAndScopes(
    debugAdapter,
    'test/basetypes.cpp',
    ['CLASS_BP'],
    'Class'
  )

  for (const scope of scopes) {
    if (scope.name == 'Arguments') {
      const vres = await debugAdapter.sendReqGetResponse('variables', { variablesReference: scope.variablesReference })
      assertAllVariableReferencesUnique(vres.body.variables)
      assertVarResponseLength(vres.body.variables, 3, scope.variablesReference, vres)

      if (!vres.body.variables.some((v) => v.name == 'this' && v.type == 'Class *')) {
        throw new Error(`Expected to see a 'this' parameter, but didn't. Variables: ${prettyJson(vres.body.variables)}`)
      }
    }
  }
}

async function scopeLocalsTest() {
  const MAIN_FILE = 'test/basetypes.cpp'
  const debugAdapter = new DAClient(MDB_PATH, [])
  let { threads, frames, scopes } = await launchToGetFramesAndScopes(
    debugAdapter,
    MAIN_FILE,
    ['LEX_BLOCK'],
    'lexical_block'
  )

  for (const scope of scopes) {
    if (scope.name == 'Locals') {
      const vres = await debugAdapter.sendReqGetResponse('variables', { variablesReference: scope.variablesReference })
      const variables = vres.body.variables
      let expectedCount = 8
      assertAllVariableReferencesUnique(variables)
      assertVarResponseLength(variables, expectedCount, scope.variablesReference, vres)

      for (const v of variables) {
        if (v.name == 'structure') {
          console.log(`[variables request]: varRef: ${v.variablesReference}, name='${v.name}'`)
          const vres = await debugAdapter.sendReqGetResponse('variables', { variablesReference: v.variablesReference })
          const variables = vres.body.variables
          assertAllVariableReferencesUnique(variables)
          assertVarResponseLength(variables, 3, scope.variablesReference, vres)
          console.log(`contents of struct Structured:\n${JSON.stringify(variables, null, 2)}`)
        }
      }
    }
  }
}

async function scopeArgsTest() {
  const MAIN_FILE = 'test/basetypes.cpp'
  const debugAdapter = new DAClient(MDB_PATH, [])
  let { threads, frames, scopes } = await launchToGetFramesAndScopes(
    debugAdapter,
    MAIN_FILE,
    ['LEX_BLOCK'],
    'lexical_block'
  )
  for (const scope of scopes) {
    if (scope.name == 'Arguments') {
      const argsResponse = await debugAdapter.sendReqGetResponse('variables', {
        variablesReference: scope.variablesReference,
      })
      const args = argsResponse.body.variables
      assertAllVariableReferencesUnique(args)
      assertVarResponseLength(args, 2, scope.variablesReference, argsResponse)
      const expectedArgs = [
        { name: 'name', type: 'const char *' },
        { name: 'should_take', type: 'bool' },
      ]
      assert.deepEqual(
        args.length,
        expectedArgs.length,
        `Expected to see ${expectedArgs.length} member variables but saw ${args.length}`
      )
      assertAllVariableReferencesUnique(args)
      for (const v of expectedArgs) {
        let arg = args.find((arg) => arg.name == v.name)
        assertEqAInB(v, arg)
      }
    }
  }
}

async function membersOfVariableTest() {
  const MAIN_FILE = 'test/basetypes.cpp'
  const debugAdapter = new DAClient(MDB_PATH, [])
  let { threads, frames, scopes } = await launchToGetFramesAndScopes(
    debugAdapter,
    MAIN_FILE,
    ['LEX_BLOCK'],
    'lexical_block'
  )

  for (const scope of scopes) {
    if (scope.name == 'Locals') {
      const vres = await debugAdapter.sendReqGetResponse('variables', { variablesReference: scope.variablesReference })
      const variables = vres.body.variables
      let expectedCount = 8
      assertAllVariableReferencesUnique(variables)

      if (variables.length != expectedCount)
        throw new Error(
          `[varRef: ${scope.variablesReference}]: Expected ${expectedCount} variables but got ${
            variables.length
          }. Variables response: ${prettyJson(vres)}`
        )

      const expected = [
        { name: 'name', type: 'const char *' },
        { name: 'count', type: 'int', value: '1', variablesReference: 0 },
        { name: 'fraction', type: 'float', value: '1.25', variablesReference: 0 },
      ]

      let struct = variables.find((v) => v.name == 'structure')
      if (struct == undefined) throw new Error(`Did not get a response containing a variable with name 'structure'`)

      const structMembersResponse = await debugAdapter.sendReqGetResponse('variables', {
        variablesReference: struct.variablesReference,
      })

      const structMembers = structMembersResponse.body.variables
      assert.deepEqual(
        structMembers.length,
        expected.length,
        `Expected to see ${expected.length} member variables but saw ${structMembers.length}`
      )
      assertAllVariableReferencesUnique(structMembers)
      for (const v of expected) {
        let member = structMembers.find((member) => member.name == v.name)
        assertEqAInB(v, member)
      }
    }
  }
}

async function returnValue() {}

async function interpretTemplateTypes() {
  const FileToSetBpIn = 'test/templated_code/template.h'
  const debugAdapter = new DAClient(MDB_PATH, [])
  let { threads, frames, scopes } = await launchToGetFramesAndScopes(
    debugAdapter,
    FileToSetBpIn,
    ['CTOR1'],
    'TemplateType',
    'templated'
  )
}

const tests = {
  scopeLocalsTest: scopeLocalsTest,
  scopeArgsTest: scopeArgsTest,
  membersOfVariableTest: membersOfVariableTest,
  inConstructor: inConstructor,
  returnValue: returnValue,
  interpretTemplateTypes: interpretTemplateTypes,
}

runTestSuite(tests)
