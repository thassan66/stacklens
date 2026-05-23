#!/usr/bin/env node

import { spawn } from "node:child_process";
import { scanProject } from "./scanner.js";
import { startDashboard } from "./server.js";

async function main() {
  const options = parseArgs(process.argv.slice(2));

  if (options.help) {
    printHelp();
    return;
  }

  const report = await scanProject(options.path);

  if (options.json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    return;
  }

  const server = await startDashboard(report, options.port);
  const url = `http://127.0.0.1:${options.port}`;
  process.stdout.write(`stacklens dashboard: ${url}\n`);
  process.stdout.write("Press Ctrl+C to stop.\n");

  if (!options.noOpen) {
    openBrowser(url);
  }

  process.on("SIGINT", () => {
    server.close(() => process.exit(0));
  });
}

function parseArgs(args) {
  const options = {
    path: process.cwd(),
    json: false,
    noOpen: false,
    port: 7070,
    help: false
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--help" || arg === "-h") options.help = true;
    else if (arg === "--json") options.json = true;
    else if (arg === "--no-open") options.noOpen = true;
    else if (arg === "--port") {
      options.port = parsePort(args[index + 1]);
      index += 1;
    } else if (arg.startsWith("--port=")) {
      options.port = parsePort(arg.slice("--port=".length));
    } else if (arg.startsWith("-")) {
      throw new Error(`Unknown option: ${arg}`);
    } else {
      options.path = arg;
    }
  }

  return options;
}

function parsePort(value) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("--port must be a valid port number");
  }
  return port;
}

function openBrowser(url) {
  const command = process.platform === "darwin" ? "open" : process.platform === "win32" ? "cmd" : "xdg-open";
  const args = process.platform === "win32" ? ["/c", "start", "", url] : [url];
  const child = spawn(command, args, { stdio: "ignore", detached: true });
  child.unref();
}

function printHelp() {
  process.stdout.write(`stacklens

Usage:
  stacklens [path] [--json] [--port <number>] [--no-open]

Options:
  --json          Print report JSON and do not start the dashboard
  --port <port>   Dashboard port, default 7070
  --no-open       Do not open the browser automatically
  -h, --help      Show this help
`);
}

main().catch((error) => {
  process.stderr.write(`stacklens: ${error.message}\n`);
  process.exitCode = 1;
});
