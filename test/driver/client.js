/** COPYRIGHT TEMPLATE */

/**
 * The DA Client driver. This file contains no tests but is included by the test to be able to spawn
 * a new mdb session. It emulates that of an Inline DA in VSCode (look at the extension `Midas` for examples)
 */
Error.stackTraceLimit = 5
const path = require('path')
const fs = require('fs')
const { spawn, ChildProcess } = require('child_process')
const EventEmitter = require('events')
const { assertLog, prettyJson, allUniqueVariableReferences, TestArgs, parseTestConfiguration } = require('./utils')
const net = require('net')

// Environment setup
const DRIVER_DIR = path.dirname(__filename)
const TEST_DIR = path.dirname(DRIVER_DIR)
const REPO_DIR = path.dirname(TEST_DIR)

let MDB_PATH = undefined

class RemoteService {
  #host
  #port
  #server

  constructor(service, host, port, binary, args = []) {
    this.#server = service
    this.#port = port
    this.#host = host
    process.on('exit', () => {
      this.#server.kill('SIGTERM')
    })
  }

  /** @returns {number} */
  get port() {
    return this.#port
  }

  /** @returns {ChildProcess} */
  get serverProcess() {
    return this.#server
  }

  get attachArgs() {
    return {
      type: 'gdbremote',
      host: this.#host,
      port: this.#port,
      allstop: false,
    }
  }
}

/**
 * @param {string} gdbserver
 * @param {string} host
 * @param {number} port
 * @param {string} binary
 * @param {string[]} args
 * @returns { Promise<RemoteService> }
 */
async function createRemoteService(gdbserver, host, port, binary, args) {
  port = Number.parseInt(port)
  return new Promise((resolve, reject) => {
    let serviceReadyEmitter = new EventEmitter()

    if (args == undefined || args == null) {
      args = []
    }
    console.log(`spawning gdbserver...`)
    let service = spawn(gdbserver, ['--multi', `${host}:${port}`, binary, ...args], {
      shell: true,
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    console.log('setup listeners')

    process.stdout.on('data', (data) => {
      console.log(`PROCESS STDOUT: ${data.toString()}`)
    })

    const waitUntilServiceReady = (data) => {
      const str = data.toString()
      console.log(`DATA: ${str}`)
      if (str.includes('Listening on port')) {
        console.log(`Ready to connect to remote service`)
        serviceReadyEmitter.emit('init', true)
      }
    }
    service.stdout.addListener('data', waitUntilServiceReady)
    service.stderr.addListener('data', waitUntilServiceReady)

    if (service == null) {
      reject(`Failed to spawn service`)
    }

    serviceReadyEmitter.once('init', (done) => {
      if (done) {
        service.stderr.removeListener('data', waitUntilServiceReady)
        service.stdout.removeListener('data', waitUntilServiceReady)
        resolve(new RemoteService(service, host, port, binary, args))
      } else {
        reject(`Failed to initialize gdb server and wait until it starts listening on the port`)
      }
    })
  })
}

function* randomSeqGenerator() {
  const min = 10000
  const max = 60000
  const set = new Set()
  while (true) {
    let value = Math.floor(Math.random() * (max - min + 1)) + min
    while (set.has(value)) {
      value = Math.floor(Math.random() * (max - min + 1)) + min
    }
    set.add(value)
    yield value
  }
}

function stringToBool(str) {
  if (typeof str !== 'string') {
    throw new Error(`str must be of string type, but was ${typeof str}`)
  }
  const lowered = str.toLowerCase()
  if (lowered === 'true') return true
  else return false
}

function envVarBool(varName) {
  const v = process.env[varName]
  if (v != undefined) {
    return stringToBool(v)
  }
  return false
}

function checkPortAvailability(maxtries = 20, host = 'localhost') {
  const portListener = (p) => {
    return new Promise((resolve, reject) => {
      const server = net.createServer()
      server.once('error', (err) => {
        if (err.code === 'EADDRINUSE') {
          resolve(false) // Port is in use
        } else {
          reject(err) // Some other error
        }
      })

      server.once('listening', () => {
        server.close()
        resolve(true) // Port is available
      })

      server.listen(p, host)
    })
  }
  return new Promise(async (resolve, reject) => {
    let tries = 0

    for (const port of randomSeqGenerator()) {
      if (tries >= maxtries) {
        reject('Max retry count hit')
      }
      const free = await portListener(port)
      if (free) {
        resolve(port)
      } else {
        tries += 1
      }
    }
  })
}

/**
 * @returns { { mdb: string, args: TestArgs } }
 */
function getExecutorArgs() {
  if (process.argv.length < 4) {
    throw new Error(
      `Test executor not received the required parameters. It requires 3 parameters.\nWorking dir: the directory from which the test is executed in\nTest suite name: The test suite\nTest name: An optional test name, if only a single test in the suite should be executed. Usage:\nnode source/to/client.js current/working/dir testSuiteName testSuite`
    )
  }
  const testArgs = new TestArgs(parseTestConfiguration(process.argv.slice(2)))

  const config = {
    mdb: testArgs.getBinary('mdb'),
    args: testArgs,
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

function readFileContents(path) {
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
    return params.flatMap((p) => p.split(' '))
  } else {
    return []
  }
}

class Thread {
  #client
  id
  name
  constructor(client, threadId, name) {
    this.#client = client
    this.id = threadId
    this.name = name
  }

  /**
   * @param {number} timeout
   * @returns {Promise<StackFrame[]>}
   */
  async stacktrace(timeout) {
    const response = await this.#client.sendReqGetResponse('stackTrace', { threadId: this.id }, timeout)
    checkResponse(response, 'stackTrace', true, this.stackTrace)
    return response.body.stackFrames.map((frame) => {
      return new StackFrame(
        this.#client,
        frame.id,
        frame.name,
        frame.line,
        frame.column,
        frame.instructionPointerReference,
        frame.source
      )
    })
  }
}

/**
 * @typedef { { variablesReference: number, name: string, value: string, type: string , evaluateName:string, namedVariables: number, indexedVariables: number, memoryReference: string } } DAPVariable
 */

class Variable {
  /** @type {DAClient} */
  #client
  /** @type { DAPVariable } */
  dap

  /** @type { Variable[] } */
  cache = null

  /**
   * @param {DAClient} client
   * @param {DAPVariable} dap
   */
  constructor(client, dap) {
    this.#client = client
    this.dap = dap
    this.cache = null
  }

  /**
   * @returns { Promise<Variable[]> }
   */
  async variables(timeout = 1000) {
    if (this.dap.variablesReference == 0) {
      throw new Error(`This variable has id == 0 it can't make any requests! DAP Object: ${JSON.stringify(this.dap)}`)
    }
    if (this.cache != null) {
      return this.cache
    }
    const {
      success,
      body: { variables },
    } = await this.#client.sendReqGetResponse('variables', { variablesReference: this.id }, timeout)
    assertLog(success, 'expected success from variables request')

    this.cache = variables.map((el) => {
      return new Variable(this.#client, el)
    })
    return this.cache
  }

  get memoryReference() {
    return this.dap.memoryReference
  }

  get value() {
    return this.dap.value
  }

  get name() {
    return this.dap.name
  }

  get type() {
    return this.dap.type
  }

  get id() {
    return this.dap.variablesReference
  }

  get variablesReference() {
    return this.dap.variablesReference
  }
}
const ScopeNames = ['Arguments', 'Locals', 'Registers']
class StackFrame {
  /** @type { DAClient } */
  #client
  /** @type { number } */
  id
  /** @type { string } */
  name

  /** @type { number } */
  line

  /** @type {string } */
  instructionPointerReference

  source
  /**
   * order of scopes is: [args, locals, registers]
   * @type { number[] }
   */
  scopes = null

  constructor(client, id, name, line, column, instructionPointerReference, source) {
    this.#client = client
    this.id = id
    this.name = name
    this.line = line
    this.column = column
    this.instructionPointerReference = instructionPointerReference
    this.source = source
    this.scopes = null
  }

  /**
   * @param {number} timeout
   * @returns {Promise<Variable[]>}
   */
  async locals(timeout = 1000) {
    await this.get_scopes()
    const {
      success,
      body: { variables },
    } = await this.#client.sendReqGetResponse('variables', { variablesReference: this.scopes[1] }, timeout)
    assertLog(success, 'expected success from variables request')

    return variables.map((v) => {
      return new Variable(this.#client, v)
    })
  }

  /**
   * @param {number} timeout
   * @returns { Promise<Variable[]> }
   */
  async args(timeout) {
    await this.get_scopes()
    const {
      success,
      body: { variables },
    } = await this.#client.sendReqGetResponse('variables', { variablesReference: this.scopes[0] }, timeout)
    assertLog(success, 'expected success from variables request')

    return variables.map((v) => {
      return new Variable(this.#client, v)
    })
  }

  async get_scopes() {
    if (this.scopes !== null) {
      return
    }

    const {
      success,
      body: { scopes },
    } = await this.#client.sendReqGetResponse('scopes', { frameId: this.id }, 1000)
    assertLog(success, `Scopes retrieved for ${this.id}`)
    assertLog(scopes.length == ScopeNames.length, `Got ${ScopeNames.length} scopes`, `Failed, got: ${scopes.length}`)
    this.scopes = []
    for (let i = 0; i < ScopeNames.length; i++) {
      this.scopes.push(scopes[i].variablesReference)
      assertLog(scopes[i].name == ScopeNames[i], `Expected scope name ${ScopeNames[i]}`, ` but was ${scopes[i].name}`)
    }
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

  /** @type { RemoteService } */
  remoteService = null

  /** @type { { mdb: string, args: TestArgs } } config */
  config

  isRemoteSession() {
    return this.remoteService !== null
  }

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
          config_args.push('-t', 12)
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
        dump_log(this.config.args.test)
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
      this.events.emit(event, body)
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

  requestedUseOfRemote() {
    return this.config.remote
  }

  buildDirFile(fileName) {
    return this.config.args.getBinary(fileName)
  }

  async setBreakpoints(filePath, lines) {
    const bp_lines = lines.map((l) => ({ line: l }))

    const args = {
      source: {
        name: repoDirFile(filePath),
        path: repoDirFile(filePath),
      },
      breakpoints: bp_lines,
    }
    const res = await this.sendReqGetResponse('setBreakpoints', args)
    const {
      success,
      body: { breakpoints },
    } = res
    assertLog(success, `expected bp request of ${JSON.stringify(bp_lines)} to succeed`, `. It failed`)
    assertLog(
      breakpoints.length == lines.length,
      `Expected ${lines.length} breakpoints`,
      `Failed to set ${lines.length} breakpoints. Response: \n${prettyJson(res)}`
    )
    return breakpoints
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
   * @returns {Promise<Thread[]>} timeout
   */
  async getThreads(timeout) {
    const threads = await this.sendReqGetResponse('threads', {}, timeout).then((res) => {
      if (!res.success) {
        throw new Error('Failed to get threads')
      }
      return res.body.threads
    })
    return threads.map((thread) => {
      return new Thread(this, thread.id, thread.name)
    })
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

    let eventCount = 0
    // we create the exception object here, to report decent stack traces for when it actually does fail.
    const err = new Error('Timed out')
    Error.captureStackTrace(err, fn)
    let p = new Promise((res, rej) => {
      let evts = []
      const listener = (body) => {
        eventCount++
        evts.push(body)
        if (evts.length == n) {
          this.events.removeListener(evt, listener)
          res(evts)
        }
      }
      this.events.on(evt, listener)
    })

    return Promise.race([
      p.then((res) => {
        clearTimeout(timeOut)
        return res
      }),
      new Promise((_, rej) => {
        signal.addEventListener('abort', () => {
          err.message = `Timed out (${timeout}ms threshold crossed): Waiting for ${n} events of type ${evt} to have happened (but saw ${eventCount})`
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
  async sendReqGetResponse(req, args, failureTimeout = seconds(1), fn = this.sendReqGetResponse) {
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
          err.message = `Timed out (${failureTimeout} milliseconds threshold crossed) waiting for response from request ${req}`
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

  async #startRunToMainNative(launchArgs, timeout) {
    let stopped_promise = this.prepareWaitForEventN('stopped', 1, timeout, this.#startRunToMainNative)
    console.log(`Starting NATIVE session: launchArguments: ${JSON.stringify(launchArgs)}`)
    let launch_res = await this.sendReqGetResponse(
      'launch',
      {
        program: launchArgs['program'],
        stopOnEntry: launchArgs['stopOnEntry'],
      },
      timeout
    )
    checkResponse(launch_res, 'launch', true)
    await this.sendReqGetResponse('configurationDone', {}, timeout)
    return stopped_promise
  }

  async #startRunToMainRemote(program, args, timeout) {
    const remoteServerBinaryPath = this.config.args.getServerBinary()
    const host = 'localhost'
    this.remoteService = await checkPortAvailability(20, host).then((port) => {
      return createRemoteService(remoteServerBinaryPath, host, port, program, args)
    })

    if (!this.isRemoteSession()) {
      throw new Error(`Failed to spawn GDB Server on ${host}:${port}`)
    }

    let entry_stopped_promise = this.prepareWaitForEventN('stopped', 1, timeout, this.#startRunToMainRemote)
    console.log(`attach args: ${JSON.stringify(this.remoteService.attachArgs, null, 2)}`)
    const attach_res = await this.sendReqGetResponse('attach', this.remoteService.attachArgs, timeout)
    checkResponse(attach_res, 'attach', true)
    const functions = ['main'].map((n) => ({ name: n }))

    const fnBreakpointResponse = await this.sendReqGetResponse('setFunctionBreakpoints', {
      breakpoints: functions,
    })
    await entry_stopped_promise
    assertLog(
      fnBreakpointResponse.success,
      'Function breakpoints request',
      `Response failed with contents: ${JSON.stringify(fnBreakpointResponse)}`
    )
    assertLog(
      fnBreakpointResponse.body.breakpoints.length == 1,
      'Expected 1 breakpoint returned',
      `But received ${JSON.stringify(fnBreakpointResponse.body.breakpoints)}`
    )
    const thrs = await this.threads(timeout)
    const threadId = thrs[0].id
    await this.sendReqGetResponse('configurationDone', {}, timeout)
    let hit_main_stopped_promise = this.prepareWaitForEventN('stopped', 1, timeout, this.#startRunToMainRemote)
    const cont = await this.sendReqGetResponse(
      'continue',
      {
        threadId: threadId,
        singleThread: false,
      },
      timeout,
      this.#startRunToMainRemote
    )
    checkResponse(cont, 'continue', true)
    return hit_main_stopped_promise
  }

  async startRunToMain(program, args = [], timeout = seconds(1)) {
    let init_res = await this.sendReqGetResponse('initialize', {}, timeout)
    checkResponse(init_res, 'initialize', true)
    switch (this.config.args.getArg('session')) {
      case 'remote': {
        return await this.#startRunToMainRemote(program, args, timeout)
      }
      case 'native': {
        return await this.#startRunToMainNative(
          {
            program: program,
            stopOnEntry: true,
          },
          timeout
        )
      }
      default:
        throw new Error(`Unknown session kind`)
    }
  }

  // utility function to initialize, launch `program` and run to `main`
  async launchToMain(program, timeout = seconds(1)) {
    let stopped_promise = this.prepareWaitForEventN('stopped', 1, timeout, this.launchToMain)
    let init_res = await this.sendReqGetResponse('initialize', {}, timeout)
    checkResponse(init_res, 'initialize', true)
    let launch_res = await this.sendReqGetResponse(
      'launch',
      {
        program: program,
        stopOnEntry: true,
      },
      timeout
    )
    checkResponse(launch_res, 'launch', true)
    await this.sendReqGetResponse('configurationDone', {}, timeout)
    await stopped_promise
  }

  async remoteAttach(attachArgs, init, timeout = seconds(1)) {
    let stopped_promise = this.prepareWaitForEventN('stopped', 1, timeout, this.remoteAttach)
    if (init) {
      let init_res = await this.sendReqGetResponse('initialize', {}, timeout)
      checkResponse(init_res, 'initialize', true)
    }

    console.log(`attach args: ${JSON.stringify(attachArgs)}`)

    let attach_res = await this.sendReqGetResponse(
      'attach',
      {
        type: attachArgs['type'] ?? 'gdbremote',
        host: attachArgs['host'],
        port: attachArgs['port'],
      },
      timeout
    )
    checkResponse(attach_res, 'attach', true)
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
  const mdblog = fs.readFileSync(path.join(process.cwd(), 'core.log'))
  fs.writeFileSync(path.join(process.cwd(), `core_${path.basename(testSuite)}.log`), mdblog)
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

/**
 *
 * @param { { mdb: string, args: TestArgs } } config
 * @param {*} tests
 */
async function runTestSuite(config, tests) {
  for (const testName in tests) {
    if (config.args.test != undefined) {
      if (config.args.test == testName) {
        const DA = new DAClient(config.mdb, [], config)
        const testFn = tests[testName]()
        await runTest(DA, testFn)
      }
    } else {
      const DA = new DAClient(config.mdb, [], config)
      const testFn = tests[testName]()
      await runTest(DA, testFn)
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

const IdentifierToken = '// #'
function allBreakpointIdentifiers(relativeTestFilePath) {
  const file = readFileContents(repoDirFile(relativeTestFilePath))
  const result = []
  let lineIdx = 1
  for (const line of file.split('\n')) {
    const pos = line.indexOf(IdentifierToken)
    if (pos != -1) {
      const identifier = line.substring(pos + IdentifierToken.length)
      result.push({ line: lineIdx, identifier })
    }
    lineIdx++
  }
  return result
}

async function SetBreakpoints(debugAdapter, filePath, bpIdentifiers) {
  const file = readFileContents(repoDirFile(filePath))
  const bp_lines = bpIdentifiers
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))
  assertLog(
    bp_lines.length == bpIdentifiers.length,
    `Expected ${bpIdentifiers.length} bp identifiers to be found`,
    `Could not find some of these identifiers: ${bpIdentifiers}`
  )
  const args = {
    source: {
      name: repoDirFile(filePath),
      path: repoDirFile(filePath),
    },
    breakpoints: bp_lines,
  }
  const bkpt_res = await debugAdapter.sendReqGetResponse('setBreakpoints', args)
  assertLog(
    bkpt_res.body.breakpoints.length == bpIdentifiers.length,
    `Expected ${bpIdentifiers.length} breakpoints`,
    `Failed to set ${bpIdentifiers.length} breakpoints. Response: \n${prettyJson(bkpt_res)}`
  )
  return bkpt_res
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
 * @param { string } exeFile - the binary to execute
 * @returns { { threads: object[], frames: object[], scopes: object[], bpres: object[] } }
 */
async function launchToGetFramesAndScopes(DA, filePath, bpIdentifiers, expectedFrameName, exeFile) {
  await DA.startRunToMain(DA.buildDirFile(exeFile), [], 5000)
  const bpres = await SetBreakpoints(DA, filePath, bpIdentifiers)
  console.log(`bpres: ${JSON.stringify(bpres)}`)
  const threads = await DA.threads()
  console.log(`threads: ${JSON.stringify(threads)}`)
  await DA.contNextStop(threads[0].id)
  const fres = await DA.stackTrace(threads[0].id, 1000)
  const frames = fres.body.stackFrames
  assertLog(
    frames[0].name == expectedFrameName,
    () => `Expected to be inside of frame '${expectedFrameName}`,
    () => `Actual frame=${frames[0].name}. Stacktrace:\n${prettyJson(frames)}`
  )

  const scopes_res = await DA.sendReqGetResponse('scopes', { frameId: frames[0].id })
  const scopes = scopes_res.body.scopes
  assertLog(
    scopes.length == 3,
    `expected 3 scopes`,
    `Got ${scopes.length} scopes. Scopes response: ${prettyJson(scopes_res)}`
  )
  assertLog(
    allUniqueVariableReferences(scopes),
    `Expected unique variableReference for all scopes`,
    `Scopes:\n${prettyJson(scopes)}`
  )

  return { threads, frames, scopes, bpres }
}

const SubjectSourceFiles = {
  include: {
    game: 'test/include/game.h',
    inheritance: 'test/include/inheritance.h',
    people: 'test/include/people.h',
  },
  subjects: {
    events: {
      output: 'test/subjects/events/output.h',
    },
    variablesRequest: {
      arrayOf3: 'test/subjects/variablesRequest/arrayOf3.cpp',
      pointer: 'test/subjects/variablesRequest/pointer.cpp',
      struct: 'test/subjects/variablesRequest/struct.cpp',
    },
  },
}

module.exports = {
  MDB_PATH,
  DAClient,
  SubjectSourceFiles,
  allBreakpointIdentifiers,
  getLineOf,
  getStackFramePc,
  readFileContents,
  repoDirFile,
  seconds,
  testException,
  testSuccess,
  runTestSuite,
  getRequestedTest,
  checkResponse,
  doSomethingDelayed,
  getExecutorArgs,
  launchToGetFramesAndScopes,
  SetBreakpoints,
  checkPortAvailability,
  getRandomNumber: randomSeqGenerator,
  createRemoteService,
  RemoteService,
  Thread,
  StackFrame,
  Variable,
}
