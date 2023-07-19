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
  console.error(`Tests require to pass the build directory as the developer might choose different locations for their build dir.`);
  process.exit(-1);
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
          this.mdb.stdin.write(this.serialize_request("disconnect"));
          break;
        case "output":
          break;
        case "initialized":
          break;
        case "stopped":
          break;
        default:
          console.log(`event: ${JSON.stringify(evt)}`);
          break;
      }
    });

    // Emit processed DAP Responses to this event handler
    this.events.on("response", (response) => {
      this.send_wait_res.emit(response.command, response);
    });

    this.mdb.stdout.on("data", (data) => {
      const str_data = data.toString();
      this.append_buffer(str_data);
      let msgs = this.parse_contents(this.buf.receive_buffer);
      let last_ends = 0;
      for (const { content_start, length } of msgs.filter(i => i.all_received)) {
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

  serialize_request(req, args = {}) {
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
   * 
   * @param { string } req - the request "command"
   * @param { object } args - request's arguments, as per the DAP spec: https://microsoft.github.io/debug-adapter-protocol/specification
   * @returns { Promise<{response_seq: number, type: string, success: boolean, command: string, body: object}> } - Returns a promise that resolves to the response to the `req` command.
   */
  send_req_get_response(req, args) {
    return new Promise((res) => {
      const serialized = this.serialize_request(req, args);
      this.mdb.stdin.write(serialized)
      this.send_wait_res.once(req, (response) => {
        res(response);
      })
    });
  }

  flush_connection() {
    this.mdb.stdin.write("----\n");
  }

  /**
  * @param {string} contents
  * @returns {{ content_start: number, length: number, all_received: boolean }[]}
  */
  parse_contents(contents) {
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
          const len = Number.parseInt(match)
          const all_received = (contents_start + len) <= contents.length;
          result.push({ content_start: contents_start, length: len, all_received })
        }
      });
    }
    return result;
  }

  append_buffer(data) {
    this.buf.receive_buffer = this.buf.receive_buffer.concat(data);
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

function check_response(file, response, command, expected_success = true) {
  if (response.type != "response") {
    console.error(`[${file}] Type of message was expected to be 'response' but was '${response.type}'`);
    dump_log();
    process.exit(-1);
  }
  if (response.success != expected_success) {
    console.error(`[${file}] Expected response to succeed ${expected_success} but got ${response.success}`);
    dump_log();
    process.exit(-1);
  }

  if (response.command != command) {
    console.error(`[${file}] Expected command to be ${command} but got ${response.command}`);
    dump_log();
    process.exit(-1);
  }
}

function testException(err) {
  console.error(`Test failed: ${err}`);
  process.exit(-1);
}

module.exports = {
  DRIVER_DIR,
  TEST_DIR,
  REPO_DIR,
  BUILD_BIN_DIR,
  MDB_PATH,
  check_response,
  testException,
  DAClient
}