import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  existsSync,
  rmSync,
  cpSync,
  readdirSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const version = "7.21.0";
const sha256 =
  "124727eacdb64fd6c9c1c3a78e353207ec1378d071bbdc15de79b0a30ed2ad6d";
const file = `openapi-generator-${version}.jar`;
const cache = resolve(".cache", file);
const destination = resolve("src/core/services/api/generated");
const url = `https://repo.maven.apache.org/maven2/org/openapitools/openapi-generator-cli/${version}/openapi-generator-cli-${version}.jar`;

/** verify rejects a jar unless its contents match the pinned generator release. */
function verify(bytes) {
  if (createHash("sha256").update(bytes).digest("hex") !== sha256)
    throw new Error("OpenAPI Generator checksum mismatch");
}

/** installGenerator verifies a cached artifact or fetches the pinned Maven Central release. */
async function installGenerator() {
  if (existsSync(cache)) {
    verify(readFileSync(cache));
    return;
  }
  const response = await fetch(url);
  if (!response.ok)
    throw new Error(`Generator download failed (HTTP ${response.status})`);
  const bytes = Buffer.from(await response.arrayBuffer());
  verify(bytes);
  mkdirSync(".cache", { recursive: true });
  writeFileSync(cache, bytes);
}

/** generate stages the complete client before replacing the directory reserved for generated TypeScript. */
function generate() {
  const output = mkdtempSync(join(tmpdir(), "hestia-angular-api-"));
  try {
    execFileSync(
      "java",
      [
        "-jar",
        cache,
        "generate",
        "-i",
        resolve("../backend/api/openapi.yaml"),
        "-g",
        "typescript-angular",
        "-o",
        output,
        "--global-property",
        "models,apis,supportingFiles,apiTests=false,modelTests=false,apiDocs=false,modelDocs=false",
        "--additional-properties",
        "ngVersion=21.2.26,providedIn=root,modelPropertyNaming=original,hideGenerationTimestamp=true",
      ],
      { stdio: "inherit" },
    );
    const files = readdirSync(output, { recursive: true }).filter((name) =>
      name.endsWith(".ts"),
    );
    if (
      !files.includes("api/panel.service.ts") ||
      !files.includes("model/snapshot.ts")
    )
      throw new Error("Missing generated client or snapshot model");
    rmSync(destination, { recursive: true, force: true });
    for (const name of files)
      cpSync(join(output, name), join(destination, name));
  } finally {
    rmSync(output, { recursive: true, force: true });
  }
}

await installGenerator();
generate();
