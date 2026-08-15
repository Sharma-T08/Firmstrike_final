import path from "node:path";
import { fileURLToPath } from "node:url";
import { mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";

const artifactDir = path.dirname(fileURLToPath(import.meta.url));

/*
 * IMPORTANT:
 * Do NOT compute workspaceRoot as a fixed number of
 * ".." hops from this file's own location.
 *
 * That depth changes depending on whether this code is
 * running from source (e.g. backend/src/lib/paths.ts,
 * or backend/scripts/*.ts via tsx) or from a bundled
 * build output (e.g. backend/dist/index.js) — and those
 * two cases sit at DIFFERENT depths relative to the real
 * monorepo root. A fixed "../.." broke exactly this way:
 * it worked for the bundled server but pointed one folder
 * too deep when run directly from source.
 *
 * Instead, walk upward from wherever this code happens to
 * be running until we find pnpm-workspace.yaml — the one
 * reliable marker of the actual monorepo root, regardless
 * of execution depth.
 */
function findWorkspaceRoot(startDir: string): string {
  let dir = startDir;

  while (true) {
    if (existsSync(path.join(dir, "pnpm-workspace.yaml"))) {
      return dir;
    }

    const parent = path.dirname(dir);

    if (parent === dir) {
      // Reached filesystem root without finding it.
      throw new Error(
        "Could not locate monorepo root (pnpm-workspace.yaml not found).",
      );
    }

    dir = parent;
  }
}

export const workspaceRoot = findWorkspaceRoot(artifactDir);

export const dataRoot = path.join(
  workspaceRoot,
  "data",
);

export const uploadsDir = path.join(
  dataRoot,
  "firmware",
);

export const extractsDir = path.join(
  dataRoot,
  "extracted",
);

export const reportsDir = path.join(
  dataRoot,
  "reports",
);

export async function ensureDataDirs(): Promise<void> {
  await mkdir(uploadsDir, {
    recursive: true,
  });

  await mkdir(extractsDir, {
    recursive: true,
  });

  await mkdir(reportsDir, {
    recursive: true,
  });
}

export function firmwareUploadPath(
  id: number,
  filename: string,
): string {
  const safe = filename.replace(
    /[^a-zA-Z0-9._-]/g,
    "_",
  );

  return path.join(
    uploadsDir,
    `${id}_${safe}`,
  );
}

export function firmwareExtractPath(
  scanId: number,
): string {
  return path.join(
    extractsDir,
    String(scanId),
  );
}

export function reportPath(
  firmwareId: number,
): string {
  return path.join(
    reportsDir,
    `firmware-${firmwareId}-report.txt`,
  );
}

export function reportPdfPath(
  firmwareId: number,
): string {
  return path.join(
    reportsDir,
    `firmware-${firmwareId}-report.pdf`,
  );
}