# stacklens

Local project insight dashboard for modern software stacks.

`stacklens` scans a repository, detects the stack, and opens a local dashboard with practical findings about configuration, dependencies, runtime exposure, and developer workflow risks. It does not run the target application and does not send project data anywhere.

## Quick start

```bash
npx stacklens .
```

From this repo:

```bash
npm test
npm run demo:spring
npm run demo:node
```

JSON output:

```bash
npx stacklens --json /path/to/project
```

## Current rule packs

- **Spring Boot**
  - Maven/Gradle detection
  - Spring Boot and Java version hints
  - Actuator exposure risks
  - hardcoded config secrets
  - profile-specific risk checks
  - DevTools dependency hints

- **Node.js**
  - risky package lifecycle scripts
  - remote script execution
  - package manager lockfile drift
  - hardcoded env examples
  - framework detection for React, Vue, Angular, Next.js, and Vite

- **Common**
  - Docker and Compose port/mount hints
  - GitHub Actions `write-all` and `pull_request_target` checks

## CLI

```txt
stacklens [path] [--json] [--port 7070] [--no-open]
```

Options:

- `--json`: print report JSON and do not start the dashboard
- `--port <number>`: choose dashboard port, default `7070`
- `--no-open`: start dashboard but do not open the browser
- `--help`: show help

## Why this exists

Most tools are either linters, vulnerability scanners, or heavyweight platforms. `stacklens` aims to be a fast local lens into the things teams actually ask when they open a repo:

- What stack is this?
- How do I run it safely?
- Which config looks production-risky?
- Which scripts execute automatically?
- What should reviewers look at before merge?

## Roadmap

- Python, Go, Rust, React, Vue, and Angular focused rule packs
- PR diff mode
- SARIF output
- rule documentation pages
- plugin API
- GitHub Action
- desktop app packaging

## License

MIT
