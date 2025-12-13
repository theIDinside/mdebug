const { readFileContents, repoDirFile, getLineOf } = require('./client')
const { prettyJson, assert } = require('./utils')

/** @typedef { import("./client").DebugAdapterClient } DebugAdapterClient */

/**
 * @param {DebugAdapterClient} debugAdapter
 * @param {string[]} bps
 */
async function setup(debugAdapter, bps) {
  await debugAdapter.startRunToMain(debugAdapter.buildDirFile('readMemory'))
  const file = readFileContents(repoDirFile('test/readMemory.cpp'))
  const bp_lines = bps
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))

  assert(
    bp_lines.length == bps.length,
    `Could not parse contents of ${repoDirFile('test/next.cpp')} to find all string identifiers`
  )

  const breakpoint_response = await debugAdapter.sendReqGetResponse('setBreakpoints', {
    source: {
      name: repoDirFile('test/readMemory.cpp'),
      path: repoDirFile('test/readMemory.cpp'),
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

/**
 * @param {DebugAdapterClient} debugAdapter
 */
const readAtMemoryMappedAddress = async function (debugAdapter) {
  const hardcodedMmapAddress = '0x1f21000'
  await setup(debugAdapter, ['BP1'])
  const threads = await debugAdapter.threads()
  await debugAdapter.contNextStop(threads[0].id)
  const readMemoryResponse = await debugAdapter.sendReqGetResponse('readMemory', {
    memoryReference: hardcodedMmapAddress,
    count: 255,
  })
  await debugAdapter.assert(readMemoryResponse.success, 'Read memory success', readMemoryResponse.message)
  const decodedString = Buffer.from(readMemoryResponse.body.data, 'base64').toString('hex')
  const expectedSize = 255 * 2
  await debugAdapter.assert(
    decodedString.length == expectedSize,
    `Expected size: ${expectedSize}`,
    `Was ${decodedString.length}`
  )

  const arr = []
  for (let i = 0; i < 255; ++i) {
    arr.push(i.toString(16).padStart(2, '0'))
  }

  await debugAdapter.assert(
    arr.join('') == decodedString,
    `String contents as expected`,
    () => `Contents was:\n${decodedString}\nExpected to be:\n${arr.join('')}`
  )
}

async function readShouldFailFaultyArgs(DA) {
  const hardcodedMmapAddress = '0x1f21000'
  await setup(DA, ['BP1'])
  const threads = await DA.threads()
  await DA.contNextStop(threads[0].id)
  let readMemoryResponse = await DA.sendReqGetResponse('readMemory', {})
  assert(!readMemoryResponse.success, `readMemory request expected to be unsuccessful but was successful`)
  assert(
    readMemoryResponse.message == 'Invalid request made. Arguments missing or of invalid type.',
    `Unexpected error message seen: ${readMemoryResponse.message}`
  )

  readMemoryResponse = await DA.sendReqGetResponse('readMemory', {
    memoryReference: 123,
    count: 10,
  })

  assert(!readMemoryResponse.success, `readMemory request expected to be unsuccessful but was successful`)
  assert(
    readMemoryResponse.body.errors.hasOwnProperty('memoryReference'),
    `Unexpected error message seen: ${prettyJson(readMemoryResponse.body)}`
  )

  readMemoryResponse = await DA.sendReqGetResponse('readMemory', {
    memoryReference: 123,
  })

  assert(!readMemoryResponse.success, `readMemory request expected to be unsuccessful but was successful`)
  assert(
    readMemoryResponse.body.missing.includes('count') &&
      readMemoryResponse.body.errors.hasOwnProperty('memoryReference'),
    `Unexpected error data: ${prettyJson(readMemoryResponse.body)}`
  )

  readMemoryResponse = await DA.sendReqGetResponse('readMemory', {
    memoryReference: 123,
    count: 'foo',
  })

  assert(!readMemoryResponse.success, `readMemory request expected to be unsuccessful but was successful`)
  assert(
    readMemoryResponse.body.errors.hasOwnProperty('count'),
    `Unexpected error message seen: '${prettyJson(readMemoryResponse.body)}'`
  )

  readMemoryResponse = await DA.sendReqGetResponse('readMemory', {
    memoryReference: 'FooBar',
    count: 12,
  })

  assert(!readMemoryResponse.success, `readMemory request expected to be unsuccessful but was successful`)
  assert(
    readMemoryResponse.body?.errors?.hasOwnProperty('memoryReference'),
    `Unexpected error data: ${prettyJson(readMemoryResponse.body)}`
  )

  assert(
    readMemoryResponse.message == 'Invalid request made. Arguments missing or of invalid type.',
    `Unexpected error message seen: '${readMemoryResponse.message}'`
  )
}

async function readAtMMapDetermineAddressByVariablesRequest(DA) {
  await setup(DA, ['BP1'])
  const threads = await DA.threads()
  await DA.contNextStop(threads[0].id)

  let frames = await DA.stackTrace(threads[0].id)

  const scopes_res = await DA.sendReqGetResponse('scopes', { frameId: frames.body.stackFrames[0].id })
  let scope = scopes_res.body.scopes.find((scope) => scope.name == 'Locals')
  assert(scope != null, 'could not find local scope')
  console.log(prettyJson(frames.body.stackFrames[0]))
  console.log(prettyJson(scope))
  const vres = await DA.sendReqGetResponse('variables', { variablesReference: scope.variablesReference })
  const addr = vres.body.variables.find((v) => v.name == 'addr')
  assert(addr != null, 'could not find variable with name "addr" in the locals scope')

  let address = Number.parseInt(addr.value).toString(16)
  const readMemoryResponse = await DA.sendReqGetResponse('readMemory', {
    memoryReference: address,
    count: 255,
  })
  assert(readMemoryResponse.success, `readMemory request was unsuccessful: ${readMemoryResponse.message}`)
  const decodedString = Buffer.from(readMemoryResponse.body.data, 'base64').toString('hex')
  assert(
    decodedString.length == 255 * 2,
    `Expected decoded string to be 255 * 2 bytes (bytes represent as hex pair-values) but was ${decodedString.length}. Contents:\n${decodedString}`
  )

  const arr = []
  for (let i = 0; i < 255; ++i) {
    arr.push(i.toString(16).padStart(2, '0'))
  }

  assert(
    arr.join('') == decodedString,
    () => `Unexpected content of decoded string.\nExpected value: ${arr.join('')}\nSeen value: ${decodedString}`
  )
}

const tests = {
  readAtMemoryMappedAddress: () => readAtMemoryMappedAddress,
  readAtMMapDetermineAddressByVariablesRequest: () => readAtMMapDetermineAddressByVariablesRequest,
  readShouldFailFaultyArgs: () => readShouldFailFaultyArgs,
}

module.exports = {
  tests: tests,
}
