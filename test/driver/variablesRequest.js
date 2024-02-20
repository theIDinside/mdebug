const { getLineOf, readFile, repoDirFile } = require('./client')
const { todo, assert, assertEqAInB, isHexadecimalString, prettyJson } = require('./utils')
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

function newVarObject(name, value, type, ref = (val) => !isNaN(val)) {
  return {
    name: name,
    value: value,
    type: type,
    variablesReference: ref,
    memoryReference: (val) => !isNaN(val),
  }
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
      console.log(prettyJson(vres))
      assertAllVariableReferencesUnique(vres.body.variables)
      assertVarResponseLength(vres.body.variables, 3, scope.variablesReference, vres)
      assert(
        vres.body.variables.some((v) => v.name == 'this' && v.type == 'Class *'),
        () => `Expected to see a 'this' parameter, but didn't. Variables: ${prettyJson(vres.body.variables)}`
      )
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

      const expected = {
        a: newVarObject('a', '1', 'int', 0),
        b: newVarObject('b', '3.14', 'float', 0),
        structure: newVarObject('structure', 'const Structure', 'const Structure', (value) => !isNaN(value)),
      }

      for (const v of variables.filter((v) => expected.hasOwnProperty(v.name))) {
        console.log(`variable: ${v.name}`)
        assertEqAInB(expected[v.name], v)
        if (v.name == 'structure') {
          const expected = {
            name: newVarObject('name', '0x4012c8', 'const char *'),
            count: newVarObject('count', '1', 'int', 0),
            fraction: newVarObject('fraction', '1.25', 'float', 0),
          }
          const vres = await debugAdapter.sendReqGetResponse('variables', { variablesReference: v.variablesReference })
          const variables = vres.body.variables
          assertAllVariableReferencesUnique(variables)
          assertVarResponseLength(variables, 3, scope.variablesReference, vres)
          for (const v of variables) {
            assertEqAInB(expected[v.name], v)
          }
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
      const expectedArgs = {
        name: newVarObject(
          'name',
          (val) => !isNaN(val),
          'const char *',
          (val) => val != '0' && !isNaN(val)
        ),
        should_take: newVarObject('should_take', 'true', 'bool', 0),
      }

      stdAssert.deepEqual(
        args.length,
        Object.keys(expectedArgs).length,
        `Expected to see ${expectedArgs.length} member variables but saw ${args.length}`
      )
      assertAllVariableReferencesUnique(args)
      for (const v of args) {
        assertEqAInB(expectedArgs[v.name], v)
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

async function readStringVariable(DA) {
  const hardcodedMmapAddress = '0x1f21000'
  let { threads, frames, scopes } = await launchToGetFramesAndScopes(
    DA,
    'test/readMemory.cpp',
    ['BP1'],
    'main',
    'readMemory'
  )
  let local = scopes.find((s) => s.name == 'Locals')
  assert(local != undefined, 'Could not find locals scope')
  const vres = await DA.sendReqGetResponse('variables', { variablesReference: local.variablesReference })

  const variables = vres.body.variables.filter((v) => v.name == 'hello_world' || v.name == 'str_ptr')
  assert(
    variables.length == 2,
    () =>
      `Could not find local variables 'hello_world' and 'str_ptr' in ${prettyJson(
        vres.body.variables
      )}. Result: ${prettyJson(variables)}`
  )
  console.log(prettyJson(variables))

  const hello_world = await DA.sendReqGetResponse('variables', { variablesReference: variables[0].variablesReference })
  console.log(prettyJson(hello_world))

  const strptr = await DA.sendReqGetResponse('variables', { variablesReference: variables[1].variablesReference })
  console.log(prettyJson(strptr))
}

/// This tests if `ArrayResolver` actually caches values in the correct way
/// It does this, by first requesting the variables for an array of 60 elements
/// Then the test starts by requesting 5 variables out of that array, starting from the back
/// Doing so, tests if `ArrayResolver` caches the individually requested items and then in subsequent, following requests
/// serves the correct elements back.
/// In the future, we might want to specifically tweak ArrayResolver (and it's cousins ValueResolver, CStringResolver, DefaultStructResolver et al)
/// to cache a specific amount, some multiple of N elements resulting in M bytes,
/// because we can verify that it has some property that makes it the fastest, since we're requesting data from the tracee into the supervisor.
async function testArrayResolverCaching(DA) {
  let { threads, frames, scopes } = await launchToGetFramesAndScopes(
    DA,
    'test/readMemory.cpp',
    ['ARRBP'],
    'main',
    'readMemory'
  )
  let local = scopes.find((s) => s.name == 'Locals')
  assert(local != undefined, 'Could not find locals scope')
  const vres = await DA.sendReqGetResponse('variables', { variablesReference: local.variablesReference })

  const variables = vres.body.variables.filter((v) => v.name == 'array')
  assert(
    variables.length == 1,
    () =>
      `Could not find local variables 'hello_world' and 'str_ptr' in ${prettyJson(
        vres.body.variables
      )}. Result: ${prettyJson(variables)}`
  )
  const asserter = (index, variables) => {
    console.log(`testing ${prettyJson(variables)}`)
    let expected = {
      a: newVarObject('a', `${index}`, 'int', 0),
      b: newVarObject('b', `${index + index / 100}`, 'float', 0),
    }
    for (const v of variables) {
      assertEqAInB(expected[v.name], v)
    }
  }
  const count = 5
  const arrayId = variables[0].variablesReference
  for (let i = 55; i >= 5; i -= 5) {
    console.log(`VARIABLES REQUEST FOR START=${i}`)
    const five = await DA.sendReqGetResponse('variables', {
      variablesReference: arrayId,
      start: i,
      count: count,
    })
    assert(five.body.variables.length == 5, `Expected result to be of length: ${count}`)
    let index = i
    for (const v of five.body.variables) {
      const arrTypeVariable = await DA.sendReqGetResponse('variables', {
        variablesReference: v.variablesReference,
      })
      asserter(index, arrTypeVariable.body.variables)
      index++
    }
  }
  // Array resolver should have cached all 60 elements now.
  for (let i = 0; i < 60; ++i) {
    const one = await DA.sendReqGetResponse('variables', {
      variablesReference: arrayId,
      start: i,
      count: 1,
    })
    assert(one.body.variables.length == 1, `Expected result to be of length: ${count}`)
    for (const v of one.body.variables) {
      const arrTypeVariable = await DA.sendReqGetResponse('variables', {
        variablesReference: v.variablesReference,
      })
      asserter(i, arrTypeVariable.body.variables)
    }
  }

  // Let's try it backwards
  for (let i = 59; i >= 0; --i) {
    const one = await DA.sendReqGetResponse('variables', {
      variablesReference: arrayId,
      start: i,
      count: 1,
    })
    assert(one.body.variables.length == 1, `Expected result to be of length: ${count}`)
    for (const v of one.body.variables) {
      const arrTypeVariable = await DA.sendReqGetResponse('variables', {
        variablesReference: v.variablesReference,
      })
      asserter(i, arrTypeVariable.body.variables)
    }
  }
}

async function testArrayResolverCachingDispersed(DA) {
  let { threads, frames, scopes } = await launchToGetFramesAndScopes(
    DA,
    'test/readMemory.cpp',
    ['ARRBP'],
    'main',
    'readMemory'
  )
  let local = scopes.find((s) => s.name == 'Locals')
  assert(local != undefined, 'Could not find locals scope')
  const vres = await DA.sendReqGetResponse('variables', { variablesReference: local.variablesReference })

  const variables = vres.body.variables.filter((v) => v.name == 'array')
  assert(
    variables.length == 1,
    () =>
      `Could not find local variables 'hello_world' and 'str_ptr' in ${prettyJson(
        vres.body.variables
      )}. Result: ${prettyJson(variables)}`
  )
  const asserter = (index, variables) => {
    let expected = {
      a: newVarObject('a', `${index}`, 'int', 0),
      b: newVarObject('b', `${index + index / 100}`, 'float', 0),
    }
    for (const v of variables) {
      assertEqAInB(expected[v.name], v)
    }
  }
  let count = 3
  const arrayId = variables[0].variablesReference
  for (let i = 0; i < 30; i += 5) {
    console.log(`VARIABLES REQUEST FOR START=${i} COUNT=${count}`)
    const three = await DA.sendReqGetResponse('variables', {
      variablesReference: arrayId,
      start: i,
      count: count,
    })
    assert(three.body.variables.length == count, `Expected result to be of length: ${count}`)
    let index = i
    console.log(prettyJson(three.body.variables))
    for (const v of three.body.variables) {
      const arrTypeVariable = await DA.sendReqGetResponse('variables', {
        variablesReference: v.variablesReference,
      })
      asserter(index, arrTypeVariable.body.variables)
      index++
    }
  }

  // let's see if the remaining 2 per 5 elements that were not cached, get cached and sent to us properly
  count = 5
  for (let i = 0; i < 30; i += 5) {
    console.log(`VARIABLES REQUEST FOR START=${i} COUNT=${count}`)
    const five = await DA.sendReqGetResponse('variables', {
      variablesReference: arrayId,
      start: i,
      count: count,
    })
    assert(five.body.variables.length == count, `Expected result to be of length: ${count}`)
    let index = i
    for (const v of five.body.variables) {
      const arrTypeVariable = await DA.sendReqGetResponse('variables', {
        variablesReference: v.variablesReference,
      })
      asserter(index, arrTypeVariable.body.variables)
      index++
    }
  }

  // Now go over all of them.
  for (let i = 59; i >= 0; --i) {
    const one = await DA.sendReqGetResponse('variables', {
      variablesReference: arrayId,
      start: i,
      count: 1,
    })
    assert(one.body.variables.length == 1, `Expected result to be of length: ${count}`)
    for (const v of one.body.variables) {
      const arrTypeVariable = await DA.sendReqGetResponse('variables', {
        variablesReference: v.variablesReference,
      })
      asserter(i, arrTypeVariable.body.variables)
    }
  }
}

async function readArrayTypes(DA) {
  let { threads, frames, scopes } = await launchToGetFramesAndScopes(
    DA,
    'test/readMemory.cpp',
    ['ARRBP'],
    'main',
    'readMemory'
  )
  let local = scopes.find((s) => s.name == 'Locals')
  assert(local != undefined, 'Could not find locals scope')
  const vres = await DA.sendReqGetResponse('variables', { variablesReference: local.variablesReference })

  const variables = vres.body.variables.filter((v) => v.name == 'array')
  assert(
    variables.length == 1,
    () =>
      `Could not find local variables 'hello_world' and 'str_ptr' in ${prettyJson(
        vres.body.variables
      )}. Result: ${prettyJson(variables)}`
  )
  console.log(prettyJson(variables))
  const asserter = (index, variables) => {
    console.log(`testing ${prettyJson(variables)}`)
    let expected = {
      a: newVarObject('a', `${index}`, 'int', 0),
      b: newVarObject('b', `${index + index / 100}`, 'float', 0),
    }
    for (const v of variables) {
      assertEqAInB(expected[v.name], v)
    }
  }
  const count = 5
  const arrayId = variables[0].variablesReference
  for (let i = 0; i < 55; ) {
    console.log(`VARIABLES REQUEST FOR START=${i}`)
    const five = await DA.sendReqGetResponse('variables', {
      variablesReference: arrayId,
      start: i,
      count: count,
    })
    assert(five.body.variables.length == 5, `Expected result to be of length: ${count}`)
    for (const v of five.body.variables) {
      const arrTypeVariable = await DA.sendReqGetResponse('variables', {
        variablesReference: v.variablesReference,
      })
      asserter(i, arrTypeVariable.body.variables)
      i++
    }
  }
}

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
  readStringVariable: readStringVariable,
  readArrayTypes: readArrayTypes,
  testArrayResolverCaching: testArrayResolverCaching,
  testArrayResolverCachingDispersed: testArrayResolverCachingDispersed,
}

module.exports = {
  tests: tests,
}
