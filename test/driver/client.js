/** COPYRIGHT TEMPLATE */

/**
 * The DA Client driver. This file contains no tests but is included by the test to be able to spawn
 * a new mdb session. It emulates that of an Inline DA in VSCode (look at the extension `Midas` for examples)
 */
Error.stackTraceLimit = 5
const path = require('path')
const fs = require('fs')
const { spawn } = require('child_process')
const EventEmitter = require('events')

// Environment setup
const DRIVER_DIR = path.dirname(__filename)
const TEST_DIR = path.dirname(DRIVER_DIR)
const REPO_DIR = path.dirname(TEST_DIR)

let MDB_PATH = undefined

/**
 * @returns { { mdb: string, cwd: string, testSuite: string, test: string | null } }
 */
function getExecutorArgs() {
  if (process.argv.length < 4) {
    throw new Error(
      `Test executor not received the required parameters. It requires 3 parameters.\nWorking dir: the directory from which the test is executed in\nTest suite name: The test suite\nTest name: An optional test name, if only a single test in the suite should be executed. Usage:\nnode source/to/client.js current/working/dir testSuiteName testSuite`
    )
  }
  const UserBuildDir = process.argv[2]
  const BUILD_BIN_DIR = path.join(UserBuildDir, 'bin')
  if (!fs.existsSync(BUILD_BIN_DIR)) {
    console.error(`Could not find the build directory '${BUILD_BIN_DIR}'`)
    process.exit(-1)
  }

  const config = {
    mdb: path.join(BUILD_BIN_DIR, 'mdb'),
    buildDir: BUILD_BIN_DIR,
    cwd: process.argv[2],
    testSuite: process.argv[3],
    test: process.argv[4],
  }
  return config
}

/**
 * Splits `fileData` into lines and looks for what line `string_identifier` can be found on - returns the first line where it can be found.
 * @param {string} fileData
 * @param {string} string_identifier
 */
function getLineOf(fileData, string_identifier) {
  let lineIdx = 1
  for (const line of fileData.split('\n')) {
    if (line.includes(string_identifier)) return lineIdx
    lineIdx++
  }
  return null
}

function readFile(path) {
  return fs.readFileSync(path).toString()
}

function unpackRecordArgs(param) {
  const p = param.split(';')
  const [recorder] = p.splice(0, 1)
  return { path: recorder, args: p }
}

function unpackDebuggerArgs() {
  if (process.env.hasOwnProperty('MDB')) {
    const env = process.env['MDB']
    console.log(`MDB=${env}`)
    const params = env.split(';')
    return params
  } else {
    return []
  }
}

const regex = /Content-Length: (\d+)\s{4}/gm
class DAClient {
  /** @type {EventEmitter} */
  send_wait_res
  /** @type {EventEmitter} */
  events
  /** @type {number} - Current request number */
  seq
  /** The MDB process */
  mdb

  /** @type { {next_packet_length: number, receive_buffer: string } } Parsed stdout contents */
  buf

  config

  constructor(mdb, mdb_args, config) {
    // for future work when we get recording in tests suites working.
    this.config = config
    try {
      this.recording = process.env.hasOwnProperty('REC')
      if (this.recording) {
        const parsed = unpackRecordArgs(process.env['REC'])
        const { path, args } = parsed
        console.log(`${JSON.stringify(parsed)}`)
        console.log(`Recording using ${process.env['REC']}`)
        let mdb_recorded_arg = ['-r']
        const cfg = unpackDebuggerArgs()
        if (!cfg.some((v) => v == '-t')) {
          mdb_recorded_arg.push('-t', 2)
        }
        const test_spawn_args = ['record', ...args, mdb, ...mdb_recorded_arg, ...cfg]
        console.log(`Spawning test with: ${path} ${test_spawn_args.join(' ')}`)
        this.mdb = spawn(path, test_spawn_args)
      } else {
        let config_args = unpackDebuggerArgs()
        // if no thread pool size is configured, set it to 12. MDB will attempt to automatically set it to half available threads otherwise
        if (!config_args.some((v) => v == '-t')) {
          // config_args.push('-t', 12)
        }
        console.log(`Spawning test with: ${mdb} ${config_args.join(' ')}`)
        this.mdb = spawn(mdb, [...config_args], {
          shell: true,
          stdio: 'pipe',
        })
      }
    } catch (ex) {
      console.log(`failed to spawn mdb: ${ex}`)
    }

    this.mdb.on('error', (err) => {
      console.error(`[TEST FAILED] MDB error: ${err}`)
      process.exit(-1)
    })

    this.mdb.on('exit', (exitCode) => {
      if (exitCode != 0) {
        console.error(`[TEST FAILED] MDB panicked or terminated with exit code ${exitCode}`)
        process.exit(-1)
      }
    })
    process.on('exit', (code) => {
      this.mdb.kill('SIGTERM')
      if (code != 0) {
        dump_log(this.config.testSuite)
      }
    })
    this.seq = 1
    this.send_wait_res = new EventEmitter()
    this.events = new EventEmitter()
    this.buf = {
      next_packet_length: null,
      receive_buffer: '',
    }

    // Emit processed DAP Events to this event handler
    this.events.on('event', async (evt) => {
      const { event, body } = evt
      switch (event) {
        case 'exited':
          this.mdb.stdin.write(this.serializeRequest('disconnect'))
          break
        default:
          this.events.emit(event, body)
          break
      }
    })

    // Emit processed DAP Responses to this event handler
    this.events.on('response', (response) => {
      this.send_wait_res.emit(response.command, response)
    })

    this.mdb.stdout.on('data', (data) => {
      const str_data = data.toString()
      this.appendBuffer(str_data)
      let msgs = this.parseContents(this.buf.receive_buffer)
      let last_ends = 0
      for (const { content_start, length } of msgs.filter((i) => i.all_received)) {
        const end = content_start + length
        const data = this.buf.receive_buffer.slice(content_start, end)
        try {
          const json = JSON.parse(data)
          if (!this.events.emit(json.type, json)) {
            this.events.emit('err', json)
          }
          last_ends = content_start + length
        } catch (ex) {
          console.log(`Buffer contents: '''${this.buf.receive_buffer}'''`)
          console.log(`Exception: ${ex}`)
          process.exit(-1)
        }
      }
      this.buf.receive_buffer = this.buf.receive_buffer.slice(last_ends)
    })
  }

  buildDirFile(fileName) {
    return path.join(this.config.buildDir, fileName)
  }

  serializeRequest(req, args = {}) {
    const json = {
      seq: this.seq,
      type: 'request',
      command: req,
      arguments: args,
    }
    this.seq += 1
    const data = JSON.stringify(json)
    const length = data.length
    const res = `Content-Length: ${length}\r\n\r\n${data}`
    return res
  }

  /**
   * @returns {Promise<{id: number, name: string}[]>}
   */
  async threads(timeout = seconds(1)) {
    return this.sendReqGetResponse('threads', {}, timeout)
      .then((res) => {
        return res.body.threads
      })
      .catch(testException)
  }

  /* Called _before_ an action that is expected to create an event.
   * Calling this after, may or may not work, as the event handler might not be set up in time,
   * before the actual event comes across the wire.*/
  prepareWaitForEvent(evt) {
    return new Promise((res, rej) => {
      this.events.once(evt, (body) => {
        res(body)
      })
    })
  }

  /* Called _before_ an action that is expected to create an event.
   * Calling this after, may or may not work, as the event handler might not be set up in time,
   * before the actual event comes across the wire.*/
  prepareWaitForEventN(evt, n, timeout, fn = this.prepareWaitForEventN) {
    const ctrl = new AbortController()
    const signal = ctrl.signal
    const timeOut = setTimeout(() => {
      ctrl.abort()
    }, timeout)

    let evts = []
    // we create the exception object here, to report decent stack traces for when it actually does fail.
    const err = new Error('Timed out')
    Error.captureStackTrace(err, fn)
    let p = new Promise((res, rej) => {
      this.events.on(evt, (body) => {
        evts.push(body)
        if (evts.length == n) {
          res(evts)
        }
      })
    })

    return Promise.race([
      p.then((res) => {
        clearTimeout(timeOut)
        return res
      }),
      new Promise((_, rej) => {
        signal.addEventListener('abort', () => {
          err.message = `Timed out: Waiting for ${n} events of type ${evt} to have happened (but saw ${evts.length})`
          rej(err)
        })
      }),
    ])
  }

  _sendReqGetResponseImpl(req, args) {
    return new Promise((res) => {
      const serialized = this.serializeRequest(req, args)
      this.send_wait_res.once(req, (response) => {
        res(response)
      })
      this.mdb.stdin.write(serialized)
    })
  }

  /**
   * @typedef {{response_seq: number, type: string, success: boolean, command: string, body: object}} Response
   *
   * @param { string } req - the request "command"
   * @param { object } args - request's arguments, as per the DAP spec: https://microsoft.github.io/debug-adapter-protocol/specification
   * @param { number } failureTimeout - The maximum time (in milliseconds) that we should wait for response. If the request takes longer, the test will fail.
   * @returns { Promise<Response> } - Returns a promise that resolves to the response to the `req` command.
   */
  async sendReqGetResponse(req, args, failureTimeout = seconds(2), fn = this.sendReqGetResponse) {
    const ctrl = new AbortController()
    const signal = ctrl.signal
    const req_promise = this._sendReqGetResponseImpl(req, args)
    // we create the exception object here, to report decent stack traces for when it actually does fail.
    const err = new Error('Timed out')
    Error.captureStackTrace(err, fn)
    const timeOut = setTimeout(() => {
      ctrl.abort()
    }, failureTimeout)

    return Promise.race([
      req_promise.then((res) => {
        clearTimeout(timeOut)
        return res
      }),
      new Promise((_, rej) => {
        signal.addEventListener('abort', () => {
          err.message = `Timed out waiting for response from request ${req}`
          rej(err)
        })
      }),
    ])
  }

  /**
   * @typedef {{ id: number, name: string, source: {name: string, path: string}, line: number, column: number, instructionPointerReference: string}} StackFrame
   * @param { number } threadId
   * @returns {Promise<{response_seq: number, type: string, success: boolean, command: string, body: { stackFrames: StackFrame[] }}>}
   */
  async stackTrace(threadId, timeout = 1000) {
    threadId = threadId != null ? threadId : await this.getAnyThreadId()
    const response = await this.sendReqGetResponse('stackTrace', { threadId: threadId }, timeout)
    checkResponse(response, 'stackTrace', true, this.stackTrace)
    return response
  }

  async getAnyThreadId() {
    const thrs = await this.threads()
    return thrs[0].id
  }

  flushConnection() {
    this.mdb.stdin.write('----\n')
  }

  /**
   * @param {string} contents
   * @returns {{ content_start: number, length: number, all_received: boolean }[]}
   */
  parseContents(contents) {
    let m
    const result = []
    while ((m = regex.exec(contents)) !== null) {
      // This is necessary to avoid infinite loops with zero-width matches
      if (m.index === regex.lastIndex) {
        regex.lastIndex++
      }
      // The result can be accessed through the `m`-variable.
      let contents_start = 0
      m.forEach((match, groupIndex) => {
        if (groupIndex == 0) {
          contents_start = m.index + match.length
        }
        if (groupIndex == 1) {
          const len = Number.parseInt(match)
          const all_received = contents_start + len <= contents.length
          result.push({
            content_start: contents_start,
            length: len,
            all_received,
          })
        }
      })
    }
    return result
  }

  appendBuffer(data) {
    this.buf.receive_buffer = this.buf.receive_buffer.concat(data)
  }

  // utility function to initialize, launch `program` and run to `main`
  async launchToMain(program, timeout = seconds(1)) {
    console.log(`TEST BINARY: ${program}`)
    let stopped_promise = this.prepareWaitForEventN('stopped', 1, timeout, this.launchToMain)
    let init_res = await this.sendReqGetResponse('initialize', {}, timeout)
    checkResponse(init_res, 'initialize', true)
    let launch_res = await this.sendReqGetResponse(
      'launch',
      {
        program: program,
        stopAtEntry: true,
      },
      timeout
    )
    checkResponse(launch_res, 'launch', true)
    await this.sendReqGetResponse('configurationDone', {}, timeout)
    await stopped_promise
  }

  async setInsBreakpoint(addr) {
    return this.sendReqGetResponse(
      'setInstructionBreakpoints',
      {
        breakpoints: [{ instructionReference: addr }],
      },
      1000,
      this.setInsBreakpoint
    )
  }

  async contNextStop(threadId, timeout = 1000) {
    if (threadId == null) {
      const thrs = await this.threads()
      threadId = thrs[0].id
    }
    let stopped_promise = this.prepareWaitForEventN('stopped', 1, timeout, this.contNextStop)
    await this.sendReqGetResponse(
      'continue',
      {
        threadId: threadId,
        singleThread: false,
      },
      timeout,
      this.contNextStop
    )
    return await stopped_promise
  }

  /**
   * @param { "terminate"  | "suspend" } kind
   * @param { number } timeout
   * @returns
   */
  async disconnect(kind = 'terminateDebuggee', timeout = 1000) {
    switch (kind) {
      case 'terminate':
        return this.sendReqGetResponse('disconnect', {
          terminateDebuggee: true,
        })
      case 'suspend':
        return this.sendReqGetResponse('disconnect', {
          suspendDebuggee: true,
        })
    }
  }

  /**
   *
   * @param {string} req
   * @param {object} args
   * @param {string} event
   * @param {number} failureTimeout
   * @returns {Promise<{ event_body: object, response: object }>}
   */
  async sendReqWaitEvent(req, args, event, failureTimeout, fn = this.sendReqWaitEvent) {
    const ctrl = new AbortController()
    const signal = ctrl.signal
    const err = new Error('Timed out')
    Error.captureStackTrace(err, fn)
    const event_promise = this.prepareWaitForEvent(event)
    const response = await this.sendReqGetResponse(req, args, failureTimeout, fn)
    const timeOut = setTimeout(() => {
      ctrl.abort()
    }, failureTimeout)

    return Promise.race([
      event_promise.then((event_body) => {
        clearTimeout(timeOut)
        return { event_body, response }
      }),
      new Promise((_, rej) => {
        signal.addEventListener('abort', () => {
          err.message = `Timed out waiting for event ${event} after request ${req} for ${failureTimeout}`
          rej(err)
        })
      }),
    ])
  }
}

// Since we're running in a test suite, we want individual tests to
// dump the contents of the current logs, so that they are picked up by ctest if the tests
// fail - otherwise the tests get overwritten by each other.
function dump_log(testSuite) {
  const mdblog = fs.readFileSync(path.join(process.cwd(), 'mdb.log'))
  fs.writeFileSync(path.join(process.cwd(), `mdb_${path.basename(testSuite)}.log`), mdblog)
}

function repoDirFile(filePath) {
  return path.join(REPO_DIR, filePath)
}

function checkResponse(response, command, expected_success = true, fn = checkResponse) {
  if (response.type != 'response') {
    dump_log()
    const err = new Error()
    Error.captureStackTrace(err, fn)
    err.message = `Type of message was expected to be 'response' but was '${response.type}'`
    throw err
  }
  if (response.success != expected_success) {
    dump_log()
    const err = new Error()
    Error.captureStackTrace(err, fn)
    err.message = `Expected response to succeed ${expected_success} but got ${response.success}`
    throw err
  }

  if (response.command != command) {
    dump_log()
    const err = new Error()
    Error.captureStackTrace(err, fn)
    err.message = `Expected command to be ${command} but got ${response.command}`
    throw err
  }
  return response
}

/**
 * Returns PC (as string) of stack frame `level`
 * @param {{response_seq: number, type: string, success: boolean, command: string, body: { stackFrames: StackFrame[] }}} stackTraceRes
 * @param {number} level
 * @returns {string}
 */
function getStackFramePc(stackTraceRes, level) {
  return stackTraceRes.body.stackFrames[level].instructionPointerReference
}

function testSuccess(testSuite) {
  console.log(`Test ${testSuite} succeeded`)
  process.exit(0)
}

function testException(err) {
  console.log(err)
  process.exit(-1)
}

async function runTest(DA, testFn, should_exit = true) {
  if (should_exit) testFn(DA).then(testSuccess).catch(testException)
  else testFn(DA).catch(testException)
}

async function runTestSuite(config, tests) {
  for (const testName in tests) {
    if (config.test != undefined) {
      if (config.test == testName) {
        const DA = new DAClient(config.mdb, [], config)
        await runTest(DA, tests[testName])
      }
    } else {
      const DA = new DAClient(config.mdb, [], config)
      await runTest(DA, tests[testName])
    }
  }
}

function seconds(sec) {
  return sec * 1000
}

// each test is executed like: node ./path/to/test <working dir> <desired test name>. This function returns the passed in name.
function getRequestedTest() {
  console.log(`${JSON.stringify(process.argv, null, 2)}`)
  return process.argv[3]
}

async function doSomethingDelayed(fn, delay) {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve(fn())
    }, delay)
  })
}

module.exports = {
  MDB_PATH,
  DAClient,
  getLineOf,
  getStackFramePc,
  readFile,
  repoDirFile,
  seconds,
  testException,
  testSuccess,
  runTest,
  runTestSuite,
  getRequestedTest,
  checkResponse,
  doSomethingDelayed,
  getExecutorArgs,
}
