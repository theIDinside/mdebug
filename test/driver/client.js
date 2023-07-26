/** COPYRIGHT TEMPLATE */

/**
 * The DA Client driver. This file contains no tests but is included by the test to be able to spawn
 * a new mdb session. It emulates that of an Inline DA in VSCode (look at the extension `Midas` for examples)
 */

const path = require("path");
const fs = require("fs");
const { spawn, spawnSync } = require("child_process");
const EventEmitter = require("events");

// Environment setup
const DRIVER_DIR = path.dirname(__filename);
const TEST_DIR = path.dirname(DRIVER_DIR);
const REPO_DIR = path.dirname(TEST_DIR);

const TestArgs = process.argv.slice(2);

if (TestArgs.length == 0) {
  console.error(
    `Tests require to pass the build directory as the developer might choose different locations for their build dir.`
  );
  process.exit(-1);
}

/**
 * Splits `fileData` into lines and looks for what line `string_identifier` can be found on - returns the first line where it can be found.
 * @param {string} fileData
 * @param {string} string_identifier
 */
function getLineOf(fileData, string_identifier) {
  let lineIdx = 1;
  for (const line of fileData.split("\n")) {
    if (line.includes(string_identifier)) return lineIdx;
    lineIdx++;
  }
  return null;
}

function readFile(path) {
  return fs.readFileSync(path).toString();
}

const UserBuildDir = TestArgs[0];
const BUILD_BIN_DIR = path.join(UserBuildDir, "bin");
if (!fs.existsSync(BUILD_BIN_DIR)) {
  console.error(`Could not find the build directory '${BUILD_BIN_DIR}'`);
  process.exit(-1);
}
const MDB_PATH = path.join(BUILD_BIN_DIR, "mdb");
console.log(`MDB Path: ${MDB_PATH}`);

// currently, mdb takes no args
const mdb_args = [];
// End of environment setup

const regex = /Content-Length: (\d+)\s{4}/gm;
class DAClient {
  /** @type {EventEmitter} */
  send_wait_res;
  /** @type {EventEmitter} */
  events;
  /** @type {number} - Current request number */
  seq;
  /** The MDB process */
  mdb;

  /** @type { {next_packet_length: number, receive_buffer: string } } Parsed stdout contents */
  buf;

  constructor(mdb, mdb_args) {
    // this.mdb = spawn(mdb, mdb_args, { shell: true, stdio: "inherit" });
    this.mdb = spawn(mdb, mdb_args, { shell: true, stdio: "pipe" });
    this.mdb.on("error", (err) => {
      console.error(`[TEST FAILED] MDB error: ${err}`);
      process.exit(-1);
    });
    this.mdb.on("exit", exitCode => {
      console.error(`[TEST FAILED] MDB panicked or terminated with exit code ${exitCode}`);
      process.exit(-1);
    });
    process.on("exit", () => {
      this.mdb.kill("SIGKILL");
    });
    this.seq = 1;
    this.send_wait_res = new EventEmitter();
    this.events = new EventEmitter();
    this.buf = {
      next_packet_length: null,
      receive_buffer: "",
    };

    // Emit processed DAP Events to this event handler
    this.events.on("event", async (evt) => {
      const { event, body } = evt;
      switch (event) {
        case "exited":
          this.mdb.stdin.write(this.serializeRequest("disconnect"));
          break;
        case "output":
          break;
        case "initialized":
          break;
        // we're interested in mostly a few events really, stopped being one of them, in testing
        // asynchronous messages or debug console messages are uninteresting.
        // When we get dynamic shared object debug symbol parsing, we will however want to
        // pay attention to breakpoint events (which happen during breakpoint modification)
        case "stopped":
          this.events.emit("stopped", body);
          break;
        default:
          break;
      }
    });

    // Emit processed DAP Responses to this event handler
    this.events.on("response", (response) => {
      this.send_wait_res.emit(response.command, response);
    });

    this.mdb.stdout.on("data", (data) => {
      const str_data = data.toString();
      this.appendBuffer(str_data);
      let msgs = this.parseContents(this.buf.receive_buffer);
      let last_ends = 0;
      for (const { content_start, length } of msgs.filter(
        (i) => i.all_received
      )) {
        const end = content_start + length;
        const data = this.buf.receive_buffer.slice(content_start, end);
        try {
          const json = JSON.parse(data);
          if (!this.events.emit(json.type, json)) {
            this.events.emit("err", json);
          }
          last_ends = content_start + length;
        } catch (ex) {
          console.log(`Buffer contents: '''${this.buf.receive_buffer}'''`);
          console.log(`Exception: ${ex}`);
          process.exit(-1);
        }
      }
      this.buf.receive_buffer = this.buf.receive_buffer.slice(last_ends);
    });
  }

  serializeRequest(req, args = {}) {
    const json = {
      seq: this.seq,
      type: "request",
      command: req,
      arguments: args,
    };
    this.seq += 1;
    const data = JSON.stringify(json);
    const length = data.length;
    const res = `Content-Length: ${length}\r\n\r\n${data}`;
    return res;
  }

  /**
   * @returns {Promise<{id: number, name: string}[]>}
   */
  async threads() {
    return this.sendReqGetResponse("threads", {})
      .then((res) => {
        return res.body.threads;
      })
      .catch(testException);
  }

  /* Called _before_ an action that is expected to create an event.
   * Calling this after, may or may not work, as the event handler might not be set up in time,
   * before the actual event comes across the wire.*/
  prepareWaitForEvent(evt) {
    return new Promise((res, rej) => {
      this.events.once(evt, (body) => {
        res(body);
      });
    });
  }

  /**
   * @typedef {{response_seq: number, type: string, success: boolean, command: string, body: object}} Response
   * 
   * @param { string } req - the request "command"
   * @param { object } args - request's arguments, as per the DAP spec: https://microsoft.github.io/debug-adapter-protocol/specification
   * @returns { Promise<Response> } - Returns a promise that resolves to the response to the `req` command.
   */
  sendReqGetResponse(req, args) {
    return new Promise((res) => {
      const serialized = this.serializeRequest(req, args);
      this.send_wait_res.once(req, (response) => {
        res(response);
      });
      this.mdb.stdin.write(serialized);
    });
  }

  /**
   * @typedef {{ id: number, name: string, source: {name: string, path: string}, line: number, column: number, instructionPointerReference: string}} StackFrame
   * @param { number } threadId 
   * @returns {Promise<{response_seq: number, type: string, success: boolean, command: string, body: { stackFrames: StackFrame[] }}>}
   */
  async stackTrace(threadId) {
    return this.sendReqGetResponse("stackTrace", { threadId: threadId });
  }

  flushConnection() {
    this.mdb.stdin.write("----\n");
  }

  /**
   * @param {string} contents
   * @returns {{ content_start: number, length: number, all_received: boolean }[]}
   */
  parseContents(contents) {
    let m;
    const result = [];
    while ((m = regex.exec(contents)) !== null) {
      // This is necessary to avoid infinite loops with zero-width matches
      if (m.index === regex.lastIndex) {
        regex.lastIndex++;
      }
      // The result can be accessed through the `m`-variable.
      let contents_start = 0;
      m.forEach((match, groupIndex) => {
        if (groupIndex == 0) {
          contents_start = m.index + match.length;
        }
        if (groupIndex == 1) {
          const len = Number.parseInt(match);
          const all_received = contents_start + len <= contents.length;
          result.push({
            content_start: contents_start,
            length: len,
            all_received,
          });
        }
      });
    }
    return result;
  }

  appendBuffer(data) {
    this.buf.receive_buffer = this.buf.receive_buffer.concat(data);
  }

  // utility function to initialize, launch `program` and run to `main`
  async launchToMain(program) {
    let stopped_promise = this.prepareWaitForEvent("stopped");
    await this.sendReqGetResponse("initialize", {})
      .then((response) => {
        checkResponse(__filename, response, "initialize", true);
      })
      .catch(testException);
    await this.sendReqGetResponse("launch", {
      program: program,
      stopAtEntry: true,
    })
      .then((response) => {
        checkResponse(__filename, response, "launch", true);
      })
      .catch(testException);
    await this.sendReqGetResponse("configurationDone").catch(testException);
    await stopped_promise;
  }

  async contNextStop(threadId) {
    let stopped_promise = this.prepareWaitForEvent("stopped");
    await this.sendReqGetResponse("continue", { threadId: threadId });
    return await stopped_promise;
  }

  async sendReqWaitEvent(req, args, event, failureTimeout) {
    const ctrl = new AbortController();
    const signal = ctrl.signal;
    const event_promise = this.prepareWaitForEvent(event);
    const resp_res = await this.sendReqGetResponse(req, args);
    const timeOut = setTimeout(() => {
      ctrl.abort();
    }, failureTimeout);

    return Promise.race([
      event_promise.then(res => {
        clearTimeout(timeOut);
        return res;
      }),
      new Promise((_, rej) => {
        signal.addEventListener("abort", () => {
          rej(new Error(`Timed out waiting for event ${event} after request ${req}`));
        });
      })]);
  }
}

// Since we're running in a test suite, we want individual tests to
// dump the contents of the current logs, so that they are picked up by ctest if the tests
// fail - otherwise the tests get overwritten by each other.
function dump_log() {
  const mdblog = fs.readFileSync(path.join(BUILD_BIN_DIR, "mdb.log"));
  const daplog = fs.readFileSync(path.join(BUILD_BIN_DIR, "dap.log"));
  console.log(mdblog);
  console.log(daplog);
}

function buildDirFile(fileName) {
  return path.join(BUILD_BIN_DIR, fileName);
}

function repoDirFile(filePath) {
  return path.join(REPO_DIR, filePath);
}

function checkResponse(file, response, command, expected_success = true) {
  if (response.type != "response") {
    console.error(
      `[${file}] Type of message was expected to be 'response' but was '${response.type}'`
    );
    dump_log();
    process.exit(-1);
  }
  if (response.success != expected_success) {
    console.error(
      `[${file}] Expected response to succeed ${expected_success} but got ${response.success}`
    );
    dump_log();
    process.exit(-1);
  }

  if (response.command != command) {
    console.error(
      `[${file}] Expected command to be ${command} but got ${response.command}`
    );
    dump_log();
    process.exit(-1);
  }
}

/**
 * Returns PC (as string) of stack frame `level`
 * @param {{response_seq: number, type: string, success: boolean, command: string, body: { stackFrames: StackFrame[] }}} stackTraceRes 
 * @param {number} level 
 * @returns {string} 
 */
function getStackFramePc(stackTraceRes, level) {
  return stackTraceRes.body.stackFrames[level].instructionPointerReference;
}

function testException(err) {
  console.error(`Test failed: ${err}`);
  process.exit(-1);
}

function seconds(sec) { return sec * 1000; }

module.exports = {
  DRIVER_DIR,
  TEST_DIR,
  REPO_DIR,
  BUILD_BIN_DIR,
  MDB_PATH,
  checkResponse,
  testException,
  buildDirFile,
  repoDirFile,
  getLineOf,
  readFile,
  DAClient,
  getStackFramePc,
  seconds
};
