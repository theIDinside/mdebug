/** @typedef { import("./client").DAClient } MDB */

const {
  launchToGetFramesAndScopes,
  allBreakpointIdentifiers,
  SubjectSourceFiles: { include, subjects },
} = require('./client')
const { todo, assert, assertLog, assertEqAInB, prettyJson, assertAllVariableReferencesUnique } = require('./utils')
const stdAssert = require('assert')

function newVarObject(name, value, type, ref = (val) => !isNaN(val)) {
  return {
    name: name,
    value: value,
    type: type,
    variablesReference: ref,
    memoryReference: (val) => !isNaN(val),
  }
}

/**
 * Verify that `vars` is of length `expectedCount`. `varRef` is
 * the variablesReference we requested `vars` for. `response` was the full response
 */
function assertVarResponseLength(vars, expectedCount, varRef, response) {
  assertLog(
    vars.length == expectedCount,
    `[var ref: ${varRef}]: Expected ${expectedCount} variables. `,
    `Got ${vars.length}. Variables response: ${prettyJson(response)}`
  )
}

async function inConstructor(debugAdapter) {
  let { threads, frames, scopes } = await launchToGetFramesAndScopes(
    debugAdapter,
    'test/basetypes.cpp',
    ['CLASS_BP'],
    'Class',
    'basetypes'
  )

  for (const scope of scopes) {
    if (scope.name == 'Arguments') {
      const vres = await debugAdapter.sendReqGetResponse('variables', { variablesReference: scope.variablesReference })
      console.log(prettyJson(vres))
      assertAllVariableReferencesUnique(vres.body.variables)
      assertVarResponseLength(vres.body.variables, 3, scope.variablesReference, vres)
      // clang emits `Class *` for a `this` pointer of type Class, gcc emits `Class *const` ... sigh. why gcc. why.
      assert(
        vres.body.variables.some((v) => v.name == 'this' && (v.type == 'Class *' || v.type == 'const Class *')),
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
    'lexical_block',
    'basetypes'
  )

  for (const scope of scopes) {
    if (scope.name == 'Locals') {
      const vres = await debugAdapter.sendReqGetResponse('variables', { variablesReference: scope.variablesReference })
      const variables = vres?.body?.variables
      assertLog(variables != null, 'variables', `Request failed. Response: ${JSON.stringify(vres)}`)
      const expectedCount = 7
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
            name: newVarObject('name', (val) => true, 'const char *'),
            count: newVarObject('count', '1', 'int', 0),
            fraction: newVarObject('fraction', '1.25', 'float', 0),
          }
          const vres = await debugAdapter.sendReqGetResponse('variables', { variablesReference: v.variablesReference })
          const variables = vres?.body?.variables
          assertLog(variables != null, 'variables', `Request failed. Response: ${JSON.stringify(vres)}`)
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
    'lexical_block',
    'basetypes'
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
    'lexical_block',
    'basetypes'
  )

  for (const scope of scopes) {
    if (scope.name == 'Locals') {
      const vres = await debugAdapter.sendReqGetResponse('variables', { variablesReference: scope.variablesReference })
      const variables = vres.body.variables
      const expectedCount = 7
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
    const five = await DA.sendReqGetResponse('variables', {
      variablesReference: arrayId,
      start: i,
      count: count,
    })
    assertLog(five.body.variables.length == 5, `Expected result to be of length: ${count}`)
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
    const count = 1
    const one = await DA.sendReqGetResponse('variables', {
      variablesReference: arrayId,
      start: i,
      count: count,
    })
    assertLog(one.body.variables.length == 1, `Expected result to be of length: ${count}`)
    for (const v of one.body.variables) {
      const arrTypeVariable = await DA.sendReqGetResponse('variables', {
        variablesReference: v.variablesReference,
      })
      asserter(i, arrTypeVariable.body.variables)
    }
  }

  // Let's try it backwards
  for (let i = 59; i >= 0; --i) {
    const count = 1
    const one = await DA.sendReqGetResponse('variables', {
      variablesReference: arrayId,
      start: i,
      count: count,
    })
    assertLog(one.body.variables.length == 1, `Expected result to be of length: ${count}`)
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

async function returnValue(da) {
  throw new Error('returnValue not implemented')
}
async function shadowed(da) {
  throw new Error('shadowed not implemented')
}

/**
 * @param { MDB } da
 */
async function resolvePointeeValue(da) {
  const app = da.buildDirFile('pointer')
  await da.startRunToMain(app, [], 500)
  const bplocs = allBreakpointIdentifiers(subjects.variablesRequest.pointer)
  const bps = await da.setBreakpoints(
    subjects.variablesRequest.pointer,
    bplocs.map((i) => i.line)
  )
  await da.contNextStop(null, 1000)
  const threads = await da.getThreads(100)
  {
    let { ptr, pointee } = await threads[0]
      .stacktrace(100)
      .then((frames) => frames[0].locals(1000))
      .then((vars) => vars[0])
      .then((ptr) => ptr.variables(1000).then((r) => ({ ptr: ptr, pointee: r[0] })))

    assertLog(
      pointee.memoryReference == ptr.value,
      ' expected memory reference of pointee to be identical with the value of the pointer',
      `pointee: ${pointee.memoryReference} != pointer value: ${ptr.value}`
    )
    assertLog(pointee.value == 10, 'Expected value to be 10', ` But was ${pointee.value}: ${JSON.stringify(pointee)}`)
  }

  await da.contNextStop(threads[0].id, 1000)
  {
    const { ptr, pointee } = await threads[0]
      .stacktrace(100)
      .then((frames) => frames[0].locals(100))
      .then((vars) => vars[0])
      .then((ptr) => ptr.variables(100).then((r) => ({ ptr: ptr, pointee: r[0] })))
      .catch((ex) => {
        console.log(`variables requests failed: ${ex}`)
        throw ex
      })
    assertLog(
      pointee.memoryReference == ptr.value,
      ' expected memory reference of pointee to be identical with the value of the pointer',
      `pointee: ${pointee.memoryReference} != pointer value: ${ptr.value}`
    )
    assertLog(pointee.value == 42, 'Expected value to be 42', ` But was ${pointee.value}: ${JSON.stringify(pointee)}`)
  }

  await da.contNextStop(threads[0].id, 1000)
  await da.contNextStop(threads[0].id, 1000)
  {
    const { john, jane } = await threads[0]
      .stacktrace(100)
      .then((frames) => frames[0].locals(100))
      .then(async (vars) => {
        const john = await vars[0].variables(100)
        const jane = await vars[1].variables(100)
        return { jo: john, ja: jane }
      })
      .then(async ({ jo, ja }) => {
        const john = await jo[0].variables(100)
        const jane = await ja[0].variables(100)
        return { john, jane }
      })
    const John = { pid: 1, age: 42, name: 'John Doe' }
    const Jane = { pid: 2, age: 34, name: 'Jane Doe' }
    const person_expect = async (val, expected) => {
      if (val.name == 'name') {
        const name = await val.variables(100)
        assertLog(name[0].value == expected.name, `Expected name to be '${expected.name}'`, `but was ${name[0].value}`)
      } else {
        assertLog(
          val.value == expected[val.name],
          `Expected Person.${val.name} to be ${expected[val.name]}`,
          ` But was ${val.value}`
        )
      }
    }
    for (let i = 0; i < john.length; ++i) {
      await person_expect(john[i], John)
      await person_expect(jane[i], Jane)
    }
  }
  await da.contNextStop(threads[0].id, 100)
  {
    const { ptrs, ptr } = await threads[0].stacktrace(100).then(async (frames) => {
      const [ptr] = await frames[0].locals(100).then((vars) => vars.filter((v) => v.name == 'ptr'))
      const [ptrs] = await frames[0].args(100).then((vars) => vars.filter((v) => v.name == 'ptrs'))
      return { ptrs, ptr }
    })
    console.log(`ptrs: ${JSON.stringify(ptrs)}`)
    console.log(`ptr: ${JSON.stringify(ptr)}`)
  }
}

const tests = {
  scopeLocalsTest: () => scopeLocalsTest,
  scopeArgsTest: () => scopeArgsTest,
  membersOfVariableTest: () => membersOfVariableTest,
  inConstructor: () => inConstructor,
  interpretTemplateTypes: () => interpretTemplateTypes,
  returnValue: () => todo(returnValue),
  shadowed: () => todo(shadowed),
  readStringVariable: () => readStringVariable,
  readArrayTypes: () => readArrayTypes,
  testArrayResolverCaching: () => testArrayResolverCaching,
  testArrayResolverCachingDispersed: () => testArrayResolverCachingDispersed,
  resolvePointeeValue: () => resolvePointeeValue,
}

module.exports = {
  tests: tests,
}
