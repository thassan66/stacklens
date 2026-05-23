# stacklens

Local project insight dashboard for modern software stacks.

`stacklens` scans a repository, detects the stack, then opens a local dashboard with practical insights about configuration, dependencies, runtime exposure, and developer workflow risks. It does not run the target application and does not send project data anywhere.

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

SARIF output for code scanning tools:

```bash
npx stacklens --sarif /path/to/project
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
stacklens [path] [--json | --sarif] [--fail-on high|medium|low] [--port 7070] [--no-open]
```

Options:

- `--json`: print report JSON and do not start the dashboard
- `--sarif`: print SARIF 2.1.0 JSON and do not start the dashboard
- `--fail-on <severity>`: exit with code `1` when findings meet `high`, `medium`, or `low`
- `--port <number>`: choose dashboard port, default `7070`
- `--no-open`: start dashboard but do not open the browser
- `--help`: show help

## GitHub Action

```yaml
name: stacklens

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: thassan66/stacklens@main
        with:
          path: .
          output-format: sarif
          output-file: stacklens.sarif
          fail-on: high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: stacklens.sarif
```

## Why this exists

Most tools are either linters, vulnerability scanners, or heavyweight platforms. `stacklens` aims to be a fast local lens into the things teams actually ask when they open a repo:

- What stack is this?
- How do I run it safely?
- Which config looks production-risky?
- Which scripts execute automatically?
- What should reviewers look at before merge?

## Roadmap

- Strategy: build one focused rule pack at a time. Starting every language at once would make the checks shallow.
- Package-style rule packs:
  - `@stacklens/node`
    - risky npm scripts
    - outdated package manager lockfiles
    - exposed env vars
    - dependency bloat
    - insecure script patterns
  - `@stacklens/react`
    - exposed frontend env secrets
    - large bundle hints
    - missing error boundaries
    - bad build config
    - unsafe CSP hints
  - `@stacklens/vue`
    - Vite/Vue env config
    - public runtime config risks
    - build/deploy warnings
  - `@stacklens/angular`
    - environment file drift
    - production build config issues
    - old Angular/TypeScript versions
  - `@stacklens/python`
    - missing virtualenv hints
    - risky requirements.txt
    - exposed `.env`
    - Django/Flask debug mode
    - dependency pins missing
  - `@stacklens/go`
    - Go version
    - module hygiene
    - exposed config
    - Docker build hints
    - unsafe local scripts
  - `@stacklens/rust`
    - `Cargo.toml`
    - unsafe dependency flags
    - old edition
    - build script risks
    - binary size hints
  - `@stacklens/spring`
    - current Spring Boot rules
- PR diff mode
- rule documentation pages
- plugin API
- desktop app packaging

## License

MIT
