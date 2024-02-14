const { prettyJson, getLineOf, readFile, repoDirFile, assertEqAInB } = require('./client')
const { todo, assert } = require('./utils')
const stdAssert = require('assert')

/**
 * Verify that all objects in `varRefs` have unique variablesReference value.
 */
function assertAllVariableReferencesUnique(varRefs) {
  assert(
    allUniqueVariableReferences(varRefs),
    `Duplicate variablesReferences found (that were non-zero).\nResponse:\n${prettyJson(varRefs)}`
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
  assert(
    vars.length == expectedCount,
    () =>
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
  assert(bp_lines.length == bpIdentifiers.length, `Could not find these identifiers: ${bpIdentifiers}`)
  const bkpt_res = await debugAdapter.sendReqGetResponse('setBreakpoints', {
    source: {
      name: repoDirFile(filePath),
      path: repoDirFile(filePath),
    },
    breakpoints: bp_lines,
  })
  assert(
    bkpt_res.body.breakpoints.length == bpIdentifiers.length,
    `Failed to set ${bpIdentifiers.length} breakpoints. Response: \n${prettyJson(bkpt_res)}`
  )
  return bp_lines
}

/**
 * Launch tracee to main, then set breakpoints at lines where `bpIdentifiers` can be found, issue a `threads` request
 * and issue 1 `continue` request stopping at first breakpoint. Issue a `stackTrace` request and a follow that
 * with a `scopes` request for the first frame in the stack trace.
 *
 * Returns the threads, stacktrace and the scopes of the newest frame
 * @param { DAClient } DA
 * @param { string } filePath - path to .cpp file that we are testing against
 * @param { string[] } bpIdentifiers - list of string identifiers that can be found in the .cpp file, where we set breakpoints
 * @param { string } expectedFrameName - frame name we expect to see on first stop.
 * @returns { { object[], object[], object[] } }
 */
async function launchToGetFramesAndScopes(DA, filePath, bpIdentifiers, expectedFrameName, exeFile = 'basetypes') {
  await DA.launchToMain(DA.buildDirFile(exeFile), 5000)
  await SetBreakpoints(DA, filePath, bpIdentifiers)
  const threads = await DA.threads()
  await DA.contNextStop(threads[0].id)
  const fres = await DA.stackTrace(threads[0].id, 1000)
  const frames = fres.body.stackFrames
  assert(
    frames[0].name == expectedFrameName,
    () =>
      `Expected to be inside of frame '${expectedFrameName}'. Actual: ${frames[0].name}. Stacktrace:\n${prettyJson(
        frames
      )}`
  )

  const scopes_res = await DA.sendReqGetResponse('scopes', { frameId: frames[0].id })
  const scopes = scopes_res.body.scopes
  assert(scopes.length == 3, `expected 3 scopes but got ${scopes.length}. Scopes response: ${prettyJson(scopes_res)}`)
  assert(
    allUniqueVariableReferences(scopes),
    `Expected unique variableReference for all scopes. Scopes:\n${prettyJson(scopes)}`
  )

  return { threads, frames, scopes }
}

async function inConstructor(debugAdapter) {
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

async function scopeLocalsTest(debugAdapter) {
  const MAIN_FILE = 'test/basetypes.cpp'
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
        console.log(`variable: ${v.name}`)
        if (v.name == 'a') {
          stdAssert.deepEqual(v.value, '1', `expected a=1, but was ${v.value}`)
        }
        if (v.name == 'b') {
          stdAssert.deepEqual(v.value, '3.14', `expected b=3.14, but was ${v.value}`)
        }
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

async function scopeArgsTest(debugAdapter) {
  const MAIN_FILE = 'test/basetypes.cpp'
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
      stdAssert.deepEqual(
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

async function membersOfVariableTest(debugAdapter) {
  const MAIN_FILE = 'test/basetypes.cpp'
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
      stdAssert.deepEqual(
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

const returnValue = todo('returnValue')
const shadowed = todo('shadowed')
const readStringMember = todo('readStringMember')

async function interpretTemplateTypes(debugAdapter) {
  const FileToSetBpIn = 'test/templated_code/template.h'
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
  shadowed: shadowed,
  readStringMember: readStringMember,
}

module.exports = {
  tests: tests,
}
