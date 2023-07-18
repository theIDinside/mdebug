/** COPYRIGHT TEMPLATE */

const path = require("path");
const fs = require("fs");
const { spawn, spawnSync } = require("child_process");
const EventEmitter = require("events");

const DRIVER_DIR = path.dirname(__filename);
const TEST_DIR = path.dirname(DRIVER_DIR);
const REPO_DIR = path.dirname(TEST_DIR);
const BUILD_BIN_DIR = path.join(REPO_DIR, "build-debug", "bin");
const MDB_PATH = path.join(BUILD_BIN_DIR, "mdb");

/**
 * Reads the driver test subjects file and parses it.
 * @returns { Set<String> } - A set of all the test subjects that can be used.
 */
function readTestSubjects() {
  const set = new Set();
  const test_subjects = fs.readFileSync(path.join(TEST_DIR, "driver-test-subjects"), "utf-8");
  const lines = test_subjects.split("\n");
  for (const subject of lines) {
    set.add(subject);
  }
  return set;
}

const test_subjects = readTestSubjects();

console.log(`MDB Path: ${MDB_PATH}`);
const test_subject = process.argv.slice(2);
console.log(`Command line args:`);

if (test_subject.length == 0) {
  console.error(`Test subject to test against required as a parameter. Possible test subjects: ${[...readTestSubjects().values()]}`);
  process.exit(-1);
}

if (test_subject.length > 1) {
  console.error(`Only 1 test subject should be passed as parameter per test-run. This is to differentiate between failing and succeeding tests. The script exits with an exit code 0 if successful, -1 if fail.`);
  process.exit(-1);
}


// currently, mdb takes no args
const mdb_args = [];

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
      console.log()
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
          console.log(`emitted ${JSON.stringify(json)}`);
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
    const res = `Content-Length: ${length}\n\n${data}`;
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
      console.log(`writing ${serialized}`);
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

function check_response(response, command, expected_success = true) {
  if (response.type != "response") {
    console.error(`Type of message was expected to be 'response' but was '${response.type}'`);
    process.exit(-1);
  }
  if (response.success != expected_success) {
    console.error(`Expected response to succeed ${expected_success} but got ${response.success}`);
    process.exit(-1);
  }

  if (response.command != command) {
    console.error(`Expected command to be ${command} but got ${response.command}`);
    process.exit(-1);
  }
}

module.exports = {
  DRIVER_DIR,
  TEST_DIR,
  REPO_DIR,
  BUILD_BIN_DIR,
  MDB_PATH,
  readTestSubjects,
  check_response,
  DAClient
}