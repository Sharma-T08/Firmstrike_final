import path from "node:path";

const PYTHON_SCANNER_URL =
  process.env.PYTHON_SCANNER_URL ||
  "http://127.0.0.1:8010";

export type PythonScannerResult = {
  scanId: number;
  firmwareId: number;
  status: string;

  firmware: {
    name: string;
    size: number;
    sha256: string;
    format: string;
  };

  metadata: {
    architecture: string;
    vendor: string | null;
    version: string | null;
    components: Array<
      string | {
        name: string;
        version?: string;
        type?: string;
        path?: string;
        source?: string;
      }
    >;
  };

  extraction: {
    path: string;
    filesExtracted: number;
    binwalk: {
      available: boolean;
      success: boolean;
      message: string;
    };
  };

  files: Array<{
    path: string;
    type: string;
    size: number;
    permissions: string | null;
    isSuspicious: boolean;
  }>;

  strings: {
    count: number;
    sample: string[];
  };

  staticAnalysis: {
    secrets: Array<{
      type: string;
      value: string;
      file: string;
      line: number;
      severity: string;
    }>;

    dangerous: Array<{
      name: string;
      file: string;
      line: number;
      risk: string;
      description: string;
    }>;

    vulnerabilities: Array<{
      type: string;
      severity: string;
      description: string;
      affectedFile?: string;
      file?: string;
      line?: number;
    }>;
  };

  malware: Array<{
    sha256: string;
    fileName: string;
    threatScore: number;
    virusTotalResult: string;
    isMalicious: boolean;
    detectionCount: number;
    totalEngines: number;
    indicators?: string[];
  }>;

  sbom: {
    components: Array<{
      name: string;
      version: string;
      type: string;
      path: string;
      source: string;
    }>;
  };
};

export type RunPythonScannerOptions = {
  firmwareId: number;
  scanId: number;
  filePath: string;
  extractPath: string;
};

/*
 * NOTE:
 * We intentionally do NOT run these paths through
 * path.resolve() here.
 *
 * path.resolve() on Windows treats a leading "/" as
 * "root of the current working drive" — so a stale
 * POSIX-style path like:
 *
 *   /home/vivek/Desk/data/firmware/250_x.img
 *
 * silently gets rewritten to:
 *
 *   D:\home\vivek\Desk\data\firmware\250_x.img
 *
 * which is not a real path anywhere and causes 404s
 * from the Python scanner.
 *
 * filePath and extractPath are expected to already be
 * correct, OS-native absolute paths — they must be
 * built via firmwareUploadPath() / firmwareExtractPath()
 * in lib/paths.ts (using path.join/path.resolve against
 * the current workspaceRoot) by the caller, not "fixed
 * up" here.
 */

export async function runPythonScanner(
  options: RunPythonScannerOptions,
): Promise<{
  architecture: string;
  vendor: string | null;
  version: string | null;
  components: Array<{
    name: string;
    version: string;
    type: string;
    path: string;
    source: string;
  }>;
  files: PythonScannerResult["files"];
  staticAnalysis: PythonScannerResult["staticAnalysis"];
  malware: PythonScannerResult["malware"];
  extraction: PythonScannerResult["extraction"];
  sbom: PythonScannerResult["sbom"];
}> {
  const filePath = options.filePath;
  const extractPath = options.extractPath;

  console.log("");
  console.log("========================================");
  console.log("       PYTHON SCANNER REQUEST");
  console.log("========================================");
  console.log("Firmware ID :", options.firmwareId);
  console.log("Scan ID     :", options.scanId);
  console.log("File path   :", filePath);
  console.log("Extract path:", extractPath);
  console.log("Scanner URL :", PYTHON_SCANNER_URL);
  console.log("========================================");
  console.log("");

  const controller = new AbortController();

  // Firmware extraction can take a long time.
  const timeout = setTimeout(
    () => controller.abort(),
    30 * 60 * 1000,
  );

  try {
    const response = await fetch(
      `${PYTHON_SCANNER_URL}/scan`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          firmwareId: options.firmwareId,
          scanId: options.scanId,
          filePath,
          extractPath,
        }),
        signal: controller.signal,
      },
    );

    const raw = await response.text();

    if (!response.ok) {
      throw new Error(
        `Python scanner returned HTTP ${response.status}: ${raw}`,
      );
    }

    let result: PythonScannerResult;

    try {
      result = JSON.parse(raw);
    } catch {
      throw new Error(
        `Python scanner returned invalid JSON: ${raw.slice(0, 1000)}`,
      );
    }

    if (!result.metadata) {
      throw new Error(
        "Python scanner response is missing metadata",
      );
    }

    console.log("");
    console.log("========================================");
    console.log("       PYTHON SCANNER RESULT");
    console.log("========================================");
    console.log(
      "Architecture :",
      result.metadata.architecture,
    );
    console.log(
      "Vendor       :",
      result.metadata.vendor ?? "UNKNOWN",
    );
    console.log(
      "Version      :",
      result.metadata.version ?? "UNKNOWN",
    );
    console.log(
      "Files        :",
      result.files?.length ?? 0,
    );
    console.log(
      "Secrets      :",
      result.staticAnalysis?.secrets?.length ?? 0,
    );
    console.log(
      "Dangerous    :",
      result.staticAnalysis?.dangerous?.length ?? 0,
    );
    console.log(
      "Malware      :",
      result.malware?.length ?? 0,
    );
    console.log("========================================");
    console.log("");

    return {
      architecture:
        result.metadata.architecture || "UNKNOWN",

      vendor:
        result.metadata.vendor ?? null,

      version:
        result.metadata.version ?? null,

      components:
        result.sbom?.components ?? [],

      files:
        result.files ?? [],

      staticAnalysis:
        result.staticAnalysis ?? {
          secrets: [],
          dangerous: [],
          vulnerabilities: [],
        },

      malware:
        result.malware ?? [],

      extraction:
        result.extraction,

      sbom:
        result.sbom ?? {
          components: [],
        },
    };
  } catch (error) {
    if (
      error instanceof Error &&
      error.name === "AbortError"
    ) {
      throw new Error(
        "Python firmware scanner timed out after 30 minutes",
      );
    }

    throw error;
  } finally {
    clearTimeout(timeout);
  }
}