# stacklens

Local project insight dashboard for modern software stacks.

`stacklens` scans a repository, detects the stack, then opens a local dashboard with practical insights about configuration, dependencies, runtime exposure, and developer workflow risks. It does not run the target application and does not send project data anywhere.

## Quick start

```bash
npx stacklens-cli .
```

Requires Node.js 20 or newer.
The npm package name is `stacklens-cli`; the installed command is `stacklens`.

From this repo:

```bash
npm test
npm run verify:package
npm run demo:spring
npm run demo:node
```

JSON output:

```bash
npx stacklens-cli --json /path/to/project
```

SARIF output for code scanning tools:

```bash
npx stacklens-cli --sarif /path/to/project
```

## Local install

Build and install the package tarball on your machine:

```bash
npm test
npm run verify:package
TARBALL=$(npm pack --silent)
npm install -g "./$TARBALL"
stacklens /path/to/project
```

For development from a checkout:

```bash
npm link
stacklens .
npm unlink -g stacklens
```

To publish it to npm after logging in:

```bash
npm publish
```

## Current rule packs

- **`@stacklens/spring`**
  - Maven/Gradle detection
  - Spring Boot and Java version hints
  - Actuator exposure risks
  - hardcoded config secrets
  - profile-specific risk checks
  - DevTools dependency hints

- **`@stacklens/quarkus`**
  - Maven/Gradle and Quarkus extension detection
  - production profile config warnings
  - generic endpoint credential and plain TCP hints
  - Camel tracing and Artemis credential/broker URL hints

- **`@stacklens/node`**
  - risky package lifecycle scripts
  - remote script execution
  - scripts that reference credentials or disable transport security
  - missing, mixed, or outdated package manager lockfiles
  - hardcoded env examples and committed `.env` secrets
  - dependency bloat and floating dependency ranges
  - older Node.js engine targets
  - framework detection for React, Vue, Angular, Next.js, Vite, Express, and Fastify

- **`@stacklens/react`**
  - public frontend env secrets
  - production sourcemap hints
  - missing error boundary signals
  - unsafe CSP hints

- **`@stacklens/vue`**
  - Vite and Nuxt public env secrets
  - public runtime config secrets
  - production sourcemap hints
  - development-mode build warnings

- **`@stacklens/common`**
  - Docker and Compose port/mount hints
  - GitHub Actions `write-all` and `pull_request_target` checks
  - Kubernetes, OpenShift, Argo CD, Helm, Kustomize, Jenkins, Terraform, AWS, and Azure deployment checks
  - mutable image tags, privileged containers, plain env secrets, committed Secrets, and public ingress hints
  - Helm values, Kustomize overlays, Jenkins pipelines, Terraform, CloudFormation/SAM, and Azure pipeline/template hints

## CLI

```txt
stacklens [path] [--json | --sarif] [--changed] [--base <ref>] [--fail-on high|medium|low] [--port 7070] [--no-open]
```

Options:

- `--json`: print report JSON and do not start the dashboard
- `--sarif`: print SARIF 2.1.0 JSON and do not start the dashboard
- `--changed`: only report findings in files changed against a Git base
- `--base <ref>`: Git base ref for `--changed`, default tries `origin/main` then `origin/master`
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
          changed: true
          base: ${{ github.event.pull_request.base.sha || 'origin/main' }}
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
- Additional package-style rule packs:
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
- rule documentation pages
- plugin API
- desktop app packaging

## License

MIT
