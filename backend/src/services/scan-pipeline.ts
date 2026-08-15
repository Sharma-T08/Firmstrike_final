import {
  db,
  scanResultsTable,
  firmwareTable,
  vulnerabilitiesTable,
  extractedFilesTable,
  hardcodedSecretsTable,
  dangerousFunctionsTable,
  activityTable,
  cveMatchesTable,
  malwareHashesTable,
  emulationLogsTable,
  aiReportsTable,
  sbomComponentsTable,
} from "@workspace/db";

import { eq } from "drizzle-orm";

import { logger } from "../lib/logger.js";
import { firmwareExtractPath, firmwareUploadPath } from "../lib/paths.js";

import { analyzeStaticFiles } from "./static-analyzer.js";
import { matchCvesForComponents } from "./cve.js";
import { scanExtractedBinaries } from "./malware-analyzer.js";
import { runEmulation } from "./emulation.js";
import { generateAiReport } from "./gemini.js";
import { generateSbomReport } from "./sbom-generator.js";
import { runPythonScanner } from "./python-scanner.js";

/*
 * ============================================================
 * DEDUPLICATION HELPER
 * ============================================================
 */

function dedupeByKey<T>(
  items: T[],
  keyFn: (item: T) => string,
): T[] {
  const map = new Map<string, T>();

  for (const item of items) {
    const key = keyFn(item);

    if (!map.has(key)) {
      map.set(key, item);
    }
  }

  return Array.from(map.values());
}

/*
 * ============================================================
 * RISK AGGREGATION
 * ============================================================
 */

type RiskFactors = {
  vulnCount: number;
  criticalVulnCount: number;
  highVulnCount: number;
  secretsCount: number;
  criticalSecretsCount: number;
  dangerousFunctionsCount: number;
  cveCriticalCount: number;
  cveHighCount: number;
  malwareCount: number;
};

function computeRiskLevel(
  factors: RiskFactors,
): "critical" | "high" | "medium" | "low" {
  /*
   * Any malware, critical secret, critical vulnerability,
   * or critical CVE immediately makes the firmware critical.
   */
  if (
    factors.malwareCount > 0 ||
    factors.criticalSecretsCount > 0 ||
    factors.criticalVulnCount > 0 ||
    factors.cveCriticalCount > 0
  ) {
    return "critical";
  }

  let score = 0;

  score += factors.highVulnCount * 10;
  score += factors.secretsCount * 8;
  score += factors.dangerousFunctionsCount * 6;
  score += factors.cveHighCount * 10;
  score += factors.vulnCount * 2;

  if (score >= 30) {
    return "high";
  }

  if (score > 0) {
    return "medium";
  }

  return "low";
}

/*
 * ============================================================
 * MAIN SCAN PIPELINE
 * ============================================================
 */

export async function runScanPipeline(
  firmwareId: number,
  scanId: number,
): Promise<void> {
  /*
   * ==========================================================
   * LOAD FIRMWARE
   * ==========================================================
   */

  const [fw] = await db
    .select()
    .from(firmwareTable)
    .where(eq(firmwareTable.id, firmwareId));

  /*
   * No firmware or name — can't reconstruct the upload path
   * without it.
   */

  if (!fw?.name) {
    await db
      .update(scanResultsTable)
      .set({
        status: "failed",
        progress: 100,
      })
      .where(eq(scanResultsTable.id, scanId));

    await db
      .update(firmwareTable)
      .set({
        status: "failed",
      })
      .where(eq(firmwareTable.id, firmwareId));

    return;
  }

  try {
    /*
     * ========================================================
     * 1. START
     * ========================================================
     */

    await db
      .update(scanResultsTable)
      .set({
        status: "running",
        progress: 5,
      })
      .where(eq(scanResultsTable.id, scanId));

    await db
      .update(firmwareTable)
      .set({
        status: "scanning",
      })
      .where(eq(firmwareTable.id, firmwareId));

    /*
     * ========================================================
     * 2. RE-SCAN CLEANUP
     * ========================================================
     *
     * IMPORTANT:
     * SBOM components are also deleted here.
     *
     * Otherwise every new scan inserts another copy of the
     * same SBOM components.
     */

    await db.transaction(async (tx) => {
      await tx
        .delete(extractedFilesTable)
        .where(
          eq(
            extractedFilesTable.firmwareId,
            firmwareId,
          ),
        );

      await tx
        .delete(hardcodedSecretsTable)
        .where(
          eq(
            hardcodedSecretsTable.firmwareId,
            firmwareId,
          ),
        );

      await tx
        .delete(dangerousFunctionsTable)
        .where(
          eq(
            dangerousFunctionsTable.firmwareId,
            firmwareId,
          ),
        );

      await tx
        .delete(vulnerabilitiesTable)
        .where(
          eq(
            vulnerabilitiesTable.firmwareId,
            firmwareId,
          ),
        );

      await tx
        .delete(cveMatchesTable)
        .where(
          eq(
            cveMatchesTable.firmwareId,
            firmwareId,
          ),
        );

      await tx
        .delete(malwareHashesTable)
        .where(
          eq(
            malwareHashesTable.firmwareId,
            firmwareId,
          ),
        );

      await tx
        .delete(emulationLogsTable)
        .where(
          eq(
            emulationLogsTable.firmwareId,
            firmwareId,
          ),
        );

      /*
       * FIX:
       * Remove old SBOM components before generating
       * the new SBOM.
       */
      await tx
        .delete(sbomComponentsTable)
        .where(
          eq(
            sbomComponentsTable.firmwareId,
            firmwareId,
          ),
        );
    });

    /*
     * ========================================================
     * 3. PYTHON FIRMWARE SCANNER
     * ========================================================
     */

    /*
     * IMPORTANT:
     * Never trust fw.filePath / fw.extractPath from the DB —
     * those can be stale absolute paths persisted from a
     * previous environment (e.g. WSL/Linux) that no longer
     * resolve correctly here. Always recompute fresh from the
     * current workspaceRoot, and key the extract folder by
     * scanId (not firmwareId) so concurrent scans / rescans
     * don't collide in the same directory.
     */

    const filePath = firmwareUploadPath(fw.id, fw.name);
    const extractPath = firmwareExtractPath(scanId);

    await db
      .update(scanResultsTable)
      .set({
        progress: 10,
      })
      .where(eq(scanResultsTable.id, scanId));

    console.log("");
    console.log("========================================");
    console.log("       STARTING PYTHON SCANNER");
    console.log("========================================");
    console.log("Firmware :", fw.name);
    console.log("File     :", filePath);
    console.log("Extract  :", extractPath);
    console.log("========================================");
    console.log("");

    const extraction = await runPythonScanner({
      firmwareId,
      scanId,
      filePath,
      extractPath,
    });

    /*
     * ========================================================
     * 4. DETECTED METADATA
     * ========================================================
     */

    const architecture =
      extraction.architecture || "UNKNOWN";

    const vendor =
      extraction.vendor ?? null;

    const version =
      extraction.version ?? null;

    console.log("");
    console.log("========================================");
    console.log("       FIRMWARE DETECTION");
    console.log("========================================");
    console.log(
      "Architecture :",
      architecture,
    );
    console.log(
      "Vendor       :",
      vendor ?? "UNKNOWN",
    );
    console.log(
      "Version      :",
      version ?? "UNKNOWN",
    );
    console.log(
      "Components   :",
      extraction.components.length,
    );
    console.log(
      "Files        :",
      extraction.files.length,
    );
    console.log("========================================");
    console.log("");

    logger.info(
      {
        firmwareId,
        architecture,
        vendor,
        version,
      },
      "Firmware metadata detected by Python scanner",
    );

    /*
     * ========================================================
     * 5. SAVE METADATA
     * ========================================================
     */

    await db
      .update(firmwareTable)
      .set({
        extractPath,
        architecture,
        vendor,
        version,
      })
      .where(
        eq(
          firmwareTable.id,
          firmwareId,
        ),
      );

    await db
      .update(scanResultsTable)
      .set({
        progress: 30,
      })
      .where(
        eq(
          scanResultsTable.id,
          scanId,
        ),
      );

    /*
     * ========================================================
     * 6. SAVE EXTRACTED FILES
     * ========================================================
     */

    if (extraction.files.length > 0) {
      await db.insert(extractedFilesTable).values(
        extraction.files.map((file) => ({
          firmwareId,
          path: file.path,
          type: file.type,
          size: file.size,
          permissions: file.permissions,
          isSuspicious: file.isSuspicious,
        })),
      );
    }

    console.log("");
    console.log("========== EXTRACTION RESULTS ==========");
    console.log(
      "Extract path:",
      extraction.extraction?.path ??
        extractPath,
    );
    console.log(
      "Files extracted:",
      extraction.files.length,
    );
    console.log(
      "Extraction count:",
      extraction.extraction
        ?.filesExtracted ?? 0,
    );
    console.log(
      "Binwalk available:",
      extraction.extraction
        ?.binwalk?.available ?? false,
    );
    console.log(
      "Binwalk success:",
      extraction.extraction
        ?.binwalk?.success ?? false,
    );
    console.log("========================================");
    console.log("");

    /*
     * ========================================================
     * 7. STATIC ANALYSIS
     * ========================================================
     */

    const staticAnalysis =
      await analyzeStaticFiles(
        extractPath,
        extraction.files.map(
          (file) => file.path,
        ),
      );

    /*
     * Python scanner performs:
     *
     * - secret detection
     * - dangerous function detection
     * - vulnerability detection
     *
     * TypeScript static analyzer provides additional
     * findings.
     */

    const pythonSecrets =
      extraction.staticAnalysis?.secrets ??
      [];

    const pythonDangerous =
      extraction.staticAnalysis?.dangerous ??
      [];

    const pythonVulnerabilities =
      extraction.staticAnalysis
        ?.vulnerabilities ?? [];

    /*
     * Combine and deduplicate secrets.
     */

    const combinedSecrets =
      dedupeByKey(
        [
          ...pythonSecrets,
          ...staticAnalysis.secrets,
        ],
        (s: any) =>
          `${s.type}:${
            s.file ??
            s.affectedFile ??
            ""
          }:${
            s.line ?? 0
          }:${
            s.value ?? ""
          }`,
      );

    /*
     * Combine and deduplicate dangerous functions.
     */

    const combinedDangerous =
      dedupeByKey(
        [
          ...pythonDangerous,
          ...staticAnalysis.dangerous,
        ],
        (d: any) =>
          `${d.name}:${
            d.file ??
            d.affectedFile ??
            ""
          }:${
            d.line ?? 0
          }`,
      );

    /*
     * Combine and deduplicate vulnerabilities.
     */

    const combinedVulnerabilities =
      dedupeByKey(
        [
          ...pythonVulnerabilities,
          ...staticAnalysis.vulnerabilities,
        ],
        (v: any) =>
          `${v.type}:${
            v.file ??
            v.affectedFile ??
            ""
          }:${
            v.line ?? 0
          }:${
            v.description ?? ""
          }`,
      );

    console.log("");
    console.log("========== STATIC ANALYSIS ==========");

    console.log(
      "Python secrets:",
      pythonSecrets.length,
    );

    console.log(
      "TypeScript secrets:",
      staticAnalysis.secrets.length,
    );

    console.log(
      "Total secrets (deduped):",
      combinedSecrets.length,
    );

    console.log(
      "Python dangerous:",
      pythonDangerous.length,
    );

    console.log(
      "TypeScript dangerous:",
      staticAnalysis.dangerous.length,
    );

    console.log(
      "Total dangerous (deduped):",
      combinedDangerous.length,
    );

    console.log(
      "Python vulnerabilities:",
      pythonVulnerabilities.length,
    );

    console.log(
      "TypeScript vulnerabilities:",
      staticAnalysis.vulnerabilities.length,
    );

    console.log(
      "Total vulnerabilities (deduped):",
      combinedVulnerabilities.length,
    );

    console.log("====================================");
    console.log("");

    await db
      .update(scanResultsTable)
      .set({
        progress: 50,
      })
      .where(
        eq(
          scanResultsTable.id,
          scanId,
        ),
      );

    /*
     * ========================================================
     * 8. HARD-CODED SECRETS
     * ========================================================
     */

    if (combinedSecrets.length > 0) {
      await db.insert(
        hardcodedSecretsTable,
      ).values(
        combinedSecrets.map(
          (secret: any) => ({
            firmwareId,

            type:
              secret.type,

            value:
              secret.value ??
              null,

            file:
              secret.file ??
              secret.affectedFile ??
              null,

            line:
              secret.line ??
              null,

            severity:
              secret.severity ??
              "high",
          }),
        ),
      );
    }

    /*
     * ========================================================
     * 9. DANGEROUS FUNCTIONS
     * ========================================================
     */

    if (combinedDangerous.length > 0) {
      await db.insert(
        dangerousFunctionsTable,
      ).values(
        combinedDangerous.map(
          (dangerous: any) => ({
            firmwareId,

            name:
              dangerous.name,

            file:
              dangerous.file ??
              dangerous.affectedFile ??
              null,

            line:
              dangerous.line ??
              null,

            risk:
              dangerous.risk ??
              dangerous.severity ??
              "high",

            description:
              dangerous.description ??
              `Potentially dangerous function ${dangerous.name} detected.`,
          }),
        ),
      );
    }

    /*
     * ========================================================
     * 10. VULNERABILITIES
     * ========================================================
     */

    if (
      combinedVulnerabilities.length >
      0
    ) {
      await db.insert(
        vulnerabilitiesTable,
      ).values(
        combinedVulnerabilities.map(
          (
            vulnerability: any,
          ) => ({
            firmwareId,

            type:
              vulnerability.type ??
              "Static Analysis",

            severity:
              vulnerability.severity ??
              "medium",

            description:
              vulnerability.description ??
              "Potential vulnerability detected.",

            affectedFile:
              vulnerability.affectedFile ??
              vulnerability.file ??
              null,

            line:
              vulnerability.line ??
              null,

            recommendation:
              vulnerability.recommendation ??
              "Review and remediate this vulnerability.",
          }),
        ),
      );
    }

    /*
     * ========================================================
     * 11. CVE MATCHING
     * ========================================================
     *
     * Python scanner returns structured components:
     *
     * {
     *   name,
     *   version,
     *   type,
     *   path,
     *   source
     * }
     *
     * CVE matcher expects string[].
     */

    const cveComponents =
      extraction.components.map(
        (component) =>
          `${component.name} ${component.version}`,
      );

    const cveMatches =
      await matchCvesForComponents(
        cveComponents,
      );

    if (cveMatches.length > 0) {
      await db.insert(
        cveMatchesTable,
      ).values(
        cveMatches.map(
          (cve) => ({
            firmwareId,
            ...cve,
          }),
        ),
      );
    }

    console.log("");
    console.log("========== CVE ANALYSIS ==========");

    console.log(
      "Components:",
      extraction.components.length,
    );

    console.log(
      "CVE matches:",
      cveMatches.length,
    );

    console.log("==================================");
    console.log("");

    await db
      .update(scanResultsTable)
      .set({
        progress: 65,
      })
      .where(
        eq(
          scanResultsTable.id,
          scanId,
        ),
      );

    /*
     * ========================================================
     * 12. MALWARE ANALYSIS
     * ========================================================
     */

    let malwareResults =
      extraction.malware ?? [];

    try {
      const typescriptMalware =
        await scanExtractedBinaries(
          extractPath,
          extraction.files,
        );

      malwareResults = [
        ...malwareResults,
        ...typescriptMalware,
      ];
    } catch (error) {
      logger.warn(
        {
          err: error,
          firmwareId,
        },
        "TypeScript malware analyzer failed; continuing with Python results",
      );
    }

    /*
     * Save malware results.
     */

    if (malwareResults.length > 0) {
      await db.insert(
        malwareHashesTable,
      ).values(
        malwareResults.map(
          (malware: any) => ({
            firmwareId,

            sha256:
              malware.sha256,

            threatScore:
              malware.threatScore ??
              0,

            virusTotalResult:
              malware.virusTotalResult ??
              "unknown",

            isMalicious:
              malware.isMalicious ??
              false,

            detectionCount:
              malware.detectionCount ??
              0,

            totalEngines:
              malware.totalEngines ??
              0,

            fileName:
              malware.fileName ??
              "unknown",
          }),
        ),
      );
    }

    /*
     * Explicit malware flag OR threat score >= 70.
     */

    const malwareCount =
      malwareResults.filter(
        (malware: any) =>
          malware.isMalicious === true ||
          (malware.threatScore ?? 0) >= 70,
      ).length;

    console.log("");
    console.log(
      "========== MALWARE ANALYSIS ==========",
    );

    console.log(
      "Results:",
      malwareResults.length,
    );

    console.log(
      "Malicious:",
      malwareCount,
    );

    console.log(
      "======================================",
    );
    console.log("");

    /*
     * ========================================================
     * 13. EMULATION
     * ========================================================
     */

    let emulation: any = null;
    let emulationFailed = false;

    try {
      emulation =
        await runEmulation(
          filePath,
          extractPath,
          architecture,
        );

      if (emulation) {
        await db.insert(
          emulationLogsTable,
        ).values({
          firmwareId,

          status:
            "running",

          architecture:
            emulation.architecture ??
            architecture,

          runningServices:
            JSON.stringify(
              emulation.runningServices ??
                [],
            ),

          openPorts:
            JSON.stringify(
              emulation.openPorts ??
                [],
            ),

          runtimeLogs:
            emulation.runtimeLogs ??
            "",
        });
      }
    } catch (error) {
      emulationFailed = true;

      logger.warn(
        {
          err: error,
          firmwareId,
        },
        "Emulation failed; continuing scan",
      );
    }

    await db
      .update(scanResultsTable)
      .set({
        progress: 80,
      })
      .where(
        eq(
          scanResultsTable.id,
          scanId,
        ),
      );

    /*
     * ========================================================
     * 14. SBOM
     * ========================================================
     *
     * Old SBOM components have already been deleted during
     * cleanup.
     *
     * generateSbomReport() now generates:
     *
     * - CycloneDX JSON
     * - SPDX JSON
     * - CSV
     */

    let sbomFailed = false;

    try {
      await generateSbomReport(
        firmwareId,
        extractPath,
      );

      console.log("");
      console.log(
        "========== SBOM GENERATION ==========",
      );
      console.log(
        "SBOM generation completed successfully",
      );
      console.log(
        "=====================================",
      );
      console.log("");
    } catch (error) {
      sbomFailed = true;

      logger.warn(
        {
          err: error,
          firmwareId,
        },
        "SBOM generation failed; continuing scan",
      );
    }

    /*
     * ========================================================
     * 15. AI REPORT
     * ========================================================
     */

    let aiReport: any = null;
    let aiReportFailed = false;

    try {
      aiReport =
        await generateAiReport({
          firmwareName:
            fw.name,

          architecture,

          vulnerabilities:
            combinedVulnerabilities.map(
              (
                vulnerability: any,
              ) => ({
                type:
                  vulnerability.type ??
                  "Static Analysis",

                severity:
                  vulnerability.severity ??
                  "medium",

                description:
                  vulnerability.description ??
                  "",

                file:
                  vulnerability.affectedFile ??
                  vulnerability.file ??
                  "",
              }),
            ),

          secrets:
            combinedSecrets.map(
              (secret: any) => ({
                type:
                  secret.type ??
                  "Secret",

                file:
                  secret.file ??
                  "",

                severity:
                  secret.severity ??
                  "high",
              }),
            ),

          dangerousFunctions:
            combinedDangerous.map(
              (dangerous: any) => ({
                name:
                  dangerous.name ??
                  "",

                file:
                  dangerous.file ??
                  "",

                risk:
                  dangerous.risk ??
                  dangerous.severity ??
                  "high",
              }),
            ),

          cveIds:
            cveMatches.map(
              (cve) =>
                cve.cveId,
            ),

          malwareFindings:
            malwareResults.map(
              (malware: any) => ({
                fileName:
                  malware.fileName,

                threatScore:
                  malware.threatScore,

                result:
                  malware.virusTotalResult,
              }),
            ),

          /*
           * Gemini expects string[].
           */

          components:
            extraction.components.map(
              (component) =>
                `${component.name} ${component.version} (${component.type})`,
            ),
        });

      /*
       * Save AI report.
       */

      if (aiReport) {
        await db
          .insert(aiReportsTable)
          .values({
            firmwareId,

            summary:
              aiReport.summary,

            riskLevel:
              aiReport.riskLevel,

            keyFindings:
              JSON.stringify(
                aiReport.keyFindings ??
                  [],
              ),

            recommendations:
              JSON.stringify(
                aiReport.recommendations ??
                  [],
              ),

            exploitProbability:
              aiReport.exploitProbability ??
              0,
          })
          .onConflictDoUpdate({
            target:
              aiReportsTable.firmwareId,

            set: {
              summary:
                aiReport.summary,

              riskLevel:
                aiReport.riskLevel,

              keyFindings:
                JSON.stringify(
                  aiReport.keyFindings ??
                    [],
                ),

              recommendations:
                JSON.stringify(
                  aiReport.recommendations ??
                    [],
                ),

              exploitProbability:
                aiReport.exploitProbability ??
                0,

              generatedAt:
                new Date(),
            },
          });
      }
    } catch (error) {
      aiReportFailed = true;

      logger.warn(
        {
          err: error,
          firmwareId,
        },
        "AI report generation failed; continuing scan",
      );
    }

    /*
     * ========================================================
     * 16. CALCULATE RISK
     * ========================================================
     */

    const criticalVulnCount =
      combinedVulnerabilities.filter(
        (v: any) =>
          v.severity ===
          "critical",
      ).length;

    const highVulnCount =
      combinedVulnerabilities.filter(
        (v: any) =>
          v.severity ===
          "high",
      ).length;

    const criticalSecretsCount =
      combinedSecrets.filter(
        (s: any) =>
          (s.severity ??
            "high") ===
          "critical",
      ).length;

    const cveCriticalCount =
      cveMatches.filter(
        (c) =>
          c.severity ===
          "critical",
      ).length;

    const cveHighCount =
      cveMatches.filter(
        (c) =>
          c.severity ===
          "high",
      ).length;

    const riskLevel =
      computeRiskLevel({
        vulnCount:
          combinedVulnerabilities.length,

        criticalVulnCount,

        highVulnCount,

        secretsCount:
          combinedSecrets.length,

        criticalSecretsCount,

        dangerousFunctionsCount:
          combinedDangerous.length,

        cveCriticalCount,

        cveHighCount,

        malwareCount,
      });

    /*
     * ========================================================
     * 17. TOTAL FINDINGS
     * ========================================================
     */

    const totalFindings =
      combinedVulnerabilities.length +
      combinedSecrets.length +
      combinedDangerous.length +
      cveMatches.length +
      malwareCount;

    /*
     * ========================================================
     * 18. COMPLETE SCAN
     * ========================================================
     */

    await db
      .update(scanResultsTable)
      .set({
        status:
          "completed",

        progress:
          100,

        completedAt:
          new Date(),

        totalFiles:
          extraction.files.length,

        vulnerabilitiesFound:
          totalFindings,

        riskLevel,
      })
      .where(
        eq(
          scanResultsTable.id,
          scanId,
        ),
      );

    /*
     * ========================================================
     * 19. MARK FIRMWARE COMPLETED
     * ========================================================
     */

    await db
      .update(firmwareTable)
      .set({
        status:
          "completed",

        architecture,

        vendor,

        version,

        extractPath,
      })
      .where(
        eq(
          firmwareTable.id,
          firmwareId,
        ),
      );

    /*
     * ========================================================
     * 20. ACTIVITY LOG
     * ========================================================
     */

    await db.insert(
      activityTable,
    ).values({
      type:
        "scan_completed",

      message:
        `Scan completed: ${combinedVulnerabilities.length} vulnerabilities, ` +
        `${combinedSecrets.length} secrets, ` +
        `${combinedDangerous.length} dangerous functions, ` +
        `${cveMatches.length} CVEs, ` +
        `risk ${riskLevel.toUpperCase()}` +
        (aiReportFailed
          ? " (AI report unavailable)"
          : "") +
        (emulationFailed
          ? " (emulation failed)"
          : "") +
        (sbomFailed
          ? " (SBOM failed)"
          : ""),

      severity:
        riskLevel ===
        "critical"
          ? "critical"
          : riskLevel ===
              "high"
            ? "high"
            : "info",

      firmwareId,

      firmwareName:
        fw.name,
    });

    /*
     * ========================================================
     * 21. MALWARE ACTIVITY
     * ========================================================
     */

    if (malwareCount > 0) {
      await db.insert(
        activityTable,
      ).values({
        type:
          "malware_detected",

        message:
          `Malware indicators found in ${fw.name}`,

        severity:
          "critical",

        firmwareId,

        firmwareName:
          fw.name,
      });
    }

    /*
     * ========================================================
     * FINAL LOG
     * ========================================================
     */

    console.log("");
    console.log("========================================");
    console.log("           SCAN COMPLETED");
    console.log("========================================");

    console.log(
      "Firmware       :",
      fw.name,
    );

    console.log(
      "Architecture   :",
      architecture,
    );

    console.log(
      "Vendor         :",
      vendor ?? "UNKNOWN",
    );

    console.log(
      "Version        :",
      version ?? "UNKNOWN",
    );

    console.log(
      "Files          :",
      extraction.files.length,
    );

    console.log(
      "Secrets        :",
      combinedSecrets.length,
    );

    console.log(
      "Dangerous fns  :",
      combinedDangerous.length,
    );

    console.log(
      "Vulnerabilities:",
      combinedVulnerabilities.length,
    );

    console.log(
      "CVEs           :",
      cveMatches.length,
    );

    console.log(
      "Malware        :",
      malwareCount,
    );

    console.log(
      "Risk           :",
      riskLevel.toUpperCase(),
    );

    console.log("========================================");
    console.log("");
  } catch (err) {
    /*
     * ========================================================
     * PIPELINE FAILURE
     * ========================================================
     */

    logger.error(
      {
        err,
        firmwareId,
        scanId,
      },
      "Firmware scan pipeline failed",
    );

    await db
      .update(scanResultsTable)
      .set({
        status:
          "failed",

        progress:
          100,
      })
      .where(
        eq(
          scanResultsTable.id,
          scanId,
        ),
      );

    await db
      .update(firmwareTable)
      .set({
        status:
          "failed",
      })
      .where(
        eq(
          firmwareTable.id,
          firmwareId,
        ),
      );
  }
}