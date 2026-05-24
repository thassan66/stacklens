import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const tempRoot = await mkdtemp(path.join(os.tmpdir(), "stacklens-package-"));

try {
  const packDirectory = path.join(tempRoot, "pack");
  const installDirectory = path.join(tempRoot, "install");
  const sampleProject = path.join(tempRoot, "sample-project");
  await mkdir(packDirectory);
  await mkdir(installDirectory);
  await mkdir(sampleProject);

  const pack = await execFileAsync("npm", ["pack", "--pack-destination", packDirectory], {
    cwd: repositoryRoot,
    maxBuffer: 10 * 1024 * 1024
  });
  const tarballName = pack.stdout.trim().split(/\r?\n/).at(-1);
  const tarballPath = path.join(packDirectory, tarballName);

  await execFileAsync("npm", ["install", "--no-audit", "--no-fund", "--prefix", installDirectory, tarballPath], {
    cwd: repositoryRoot,
    maxBuffer: 10 * 1024 * 1024
  });

  const binary = process.platform === "win32"
    ? path.join(installDirectory, "node_modules", ".bin", "stacklens.cmd")
    : path.join(installDirectory, "node_modules", ".bin", "stacklens");

  const help = await execFileAsync(binary, ["--help"], { maxBuffer: 10 * 1024 * 1024 });
  if (!help.stdout.includes("stacklens") || !help.stdout.includes("--json")) {
    throw new Error("Packaged stacklens binary did not print expected help output");
  }

  await writeFile(
    path.join(sampleProject, "package.json"),
    JSON.stringify({
      scripts: {
        postinstall: "node scripts/setup.js"
      },
      dependencies: {
        express: "^5.0.0"
      }
    })
  );
  await writeFile(path.join(sampleProject, ".env.example"), "API_KEY=real-demo-key\n");

  const scan = await execFileAsync(binary, ["--json", sampleProject], {
    maxBuffer: 10 * 1024 * 1024
  });
  const report = JSON.parse(scan.stdout);
  if (report.project.name !== "sample-project" || report.summary.high < 1) {
    throw new Error("Packaged stacklens binary did not scan the sample project correctly");
  }

  process.stdout.write(`Verified package tarball: ${tarballName}\n`);
} finally {
  await rm(tempRoot, { recursive: true, force: true });
}
