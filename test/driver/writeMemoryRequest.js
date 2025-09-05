const { readFileContents, repoDirFile, getLineOf, SubjectSourceFiles } = require('./client')
const { assertLog, prettyJson } = require('./utils')
/**
 *
 * @param { import("./client").DebugAdapterClient } debugAdapter
 */
async function pokeTimesToZero(debugAdapter) {
  await debugAdapter.startRunToMain(debugAdapter.buildDirFile('stackframes'), 1000)
  const file = readFileContents(repoDirFile('test/stackframes.cpp'))
  const bp_lines = ['BP3', 'BAZ_RET_BP'].map((ident) => getLineOf(file, ident)).filter((item) => item != null)
  const breakpoints = await debugAdapter.setBreakpoints('test/stackframes.cpp', bp_lines)
  assertLog(
    breakpoints.length == bp_lines.length,
    `Expected ${bp_lines.length} breakpoints. `,
    `Got ${breakpoints.length}`
  )

  const threads = await debugAdapter.getThreads(100)
  await debugAdapter.contNextStop(threads[0].id, 100)
  {
    const { times, res_a } = await threads[0]
      .stacktrace()
      .then((frames) => frames[0])
      .then(async (frame) => {
        const locals = await frame.locals()
        const args = await frame.args()
        return { args, locals }
      })
      .then(({ args, locals }) => {
        const res_a = locals.find((i) => i.name == 'res_a')
        const times = args.find((i) => i.name == 'times')
        return { times, res_a }
      })

    assertLog(res_a.value == 1, `value of local variable res_a expected to be 1. `, `but was ${res_a.value}`)
    assertLog(times.value == 4, `value of local variable times expected to be 4. `, `but was ${times.value}`)

    // we need the base64 value to be a 4-byte value encoded as 0.
    const value = new Uint8Array([0, 0, 0, 0])
    const base64 = Buffer.from(value).toString('base64')
    const res = await debugAdapter.sendReqGetResponse(
      'writeMemory',
      { memoryReference: times.memoryReference, offset: 0, data: base64 },
      1000
    )
    assertLog(res.success, `Expected succcess for writeMemroy request`, ` Failed`)
  }
  await debugAdapter.contNextStop()
  {
    // res_a should not have been changed, due to the change in `times` and therefore still be 1
    const { times, res_a, res_b } = await threads[0]
      .stacktrace()
      .then((frames) => frames[0])
      .then(async (frame) => {
        const locals = await frame.locals()
        const args = await frame.args()
        return { args, locals }
      })
      .then(({ args, locals }) => {
        const res_a = locals.find((i) => i.name == 'res_a')
        const res_b = locals.find((i) => i.name == 'res_b')
        const times = args.find((i) => i.name == 'times')
        return { times, res_a, res_b }
      })

    assertLog(res_a.value == 1, `Expected res_a to be 1. `, `But was ${res_a.value}`)
    assertLog(res_b.value == 1, `Expected res_b to be 1. `, `But was ${res_b.value}`)
    assertLog(times.value == 0, `Expected times to be 0. `, `But was ${times.value}`)
  }
}

const tests = {
  pokeValueToZero: () => pokeTimesToZero,
}

module.exports = {
  tests: tests,
}
