import {
  Router,
  type IRouter,
} from "express";

import {
  db,
  scanResultsTable,
  firmwareTable,
  activityTable,
  extractedFilesTable,
} from "@workspace/db";

import { eq } from "drizzle-orm";

import { runScanPipeline } from "../services/scan-pipeline.js";
import { firmwareUploadPath } from "../lib/paths.js";
import {
  analyzeBinary,
  pickBinaryTarget,
} from "../services/binary-analyzer.js";

const router: IRouter =
  Router();

/*
 * ============================================================
 * START SCAN
 * ============================================================
 */

router.post(
  "/scanner/start",
  async (
    req,
    res,
  ): Promise<void> => {
    try {
      const {
        firmwareId,
      } = req.body;

      const parsedFirmwareId =
        Number(firmwareId);

      if (
        !Number.isInteger(
          parsedFirmwareId,
        ) ||
        parsedFirmwareId <= 0
      ) {
        res.status(400).json({
          error:
            "Invalid firmwareId",
        });

        return;
      }

      /*
       * Get firmware.
       */

      const [fw] =
        await db
          .select()
          .from(firmwareTable)
          .where(
            eq(
              firmwareTable.id,
              parsedFirmwareId,
            ),
          );

      if (!fw) {
        res.status(404).json({
          error:
            "Firmware not found",
        });

        return;
      }

      /*
       * A file must have been uploaded.
       *
       * NOTE:
       * We check fw.name (used to reconstruct the upload
       * path) rather than fw.filePath, since filePath is no
       * longer trusted downstream — the actual file location
       * is always recomputed fresh via firmwareUploadPath().
       */

      if (!fw.name) {
        res.status(400).json({
          error:
            "Firmware file not uploaded. Use /firmware/upload first.",
        });

        return;
      }

      /*
       * Prevent starting two scans for the same
       * firmware simultaneously.
       */

      const existingScans =
        await db
          .select()
          .from(scanResultsTable)
          .where(
            eq(
              scanResultsTable.firmwareId,
              parsedFirmwareId,
            ),
          );

      const runningScan =
        existingScans.find(
          (scan) =>
            scan.status ===
              "running" ||
            scan.status ===
              "pending",
        );

      if (runningScan) {
        res.status(409).json({
          error:
            "A scan is already running for this firmware.",
          scanId:
            runningScan.id,
        });

        return;
      }

      /*
       * Mark firmware scanning.
       */

      await db
        .update(firmwareTable)
        .set({
          status:
            "scanning",
        })
        .where(
          eq(
            firmwareTable.id,
            parsedFirmwareId,
          ),
        );

      /*
       * Create scan record.
       */

      const [scan] =
        await db
          .insert(
            scanResultsTable,
          )
          .values({
            firmwareId:
              parsedFirmwareId,

            status:
              "running",

            progress: 0,
          })
          .returning();

      /*
       * Activity.
       */

      await db
        .insert(activityTable)
        .values({
          type:
            "scan_started",

          message:
            `Scan initiated for ${fw.name}`,

          severity:
            "info",

          firmwareId:
            parsedFirmwareId,

          firmwareName:
            fw.name,
        });

      /*
       * Start asynchronously.
       *
       * IMPORTANT:
       * We deliberately do not await this.
       */

      void runScanPipeline(
        parsedFirmwareId,
        scan.id,
      ).catch(
        (error) => {
          console.error(
            "[Scanner Pipeline Unhandled Error]",
            error,
          );
        },
      );

      /*
       * Return immediately.
       */

      res
        .status(201)
        .json({
          id: scan.id,

          firmwareId:
            scan.firmwareId,

          startedAt:
            scan.startedAt.toISOString(),

          completedAt:
            null,

          status:
            scan.status,

          progress:
            scan.progress,

          totalFiles:
            null,

          vulnerabilitiesFound:
            null,

          riskLevel:
            null,
        });
    } catch (error) {
      console.error(
        "[Scanner Start Error]",
        error,
      );

      res.status(500).json({
        error:
          "Failed to start scanner",
        details:
          error instanceof Error
            ? error.message
            : String(error),
      });
    }
  },
);

/*
 * ============================================================
 * GET SCAN RESULTS
 * ============================================================
 */

router.get(
  "/scanner/results/:firmwareId",
  async (
    req,
    res,
  ): Promise<void> => {
    try {
      const raw =
        Array.isArray(
          req.params.firmwareId,
        )
          ? req.params.firmwareId[0]
          : req.params.firmwareId;

      const firmwareId =
        parseInt(
          raw,
          10,
        );

      if (
        isNaN(firmwareId)
      ) {
        res.status(400).json({
          error:
            "Invalid firmwareId",
        });

        return;
      }

      const results =
        await db
          .select()
          .from(
            scanResultsTable,
          )
          .where(
            eq(
              scanResultsTable.firmwareId,
              firmwareId,
            ),
          );

      res.json(
        results.map(
          (result) => ({
            ...result,

            startedAt:
              result.startedAt.toISOString(),

            completedAt:
              result.completedAt
                ? result.completedAt.toISOString()
                : null,
          }),
        ),
      );
    } catch (error) {
      console.error(
        "[Scanner Results Error]",
        error,
      );

      res.status(500).json({
        error:
          "Failed to fetch scan results",
      });
    }
  },
);

/*
 * ============================================================
 * GET EXTRACTED FILES
 * ============================================================
 */

router.get(
  "/scanner/files/:firmwareId",
  async (
    req,
    res,
  ): Promise<void> => {
    try {
      const raw =
        Array.isArray(
          req.params.firmwareId,
        )
          ? req.params.firmwareId[0]
          : req.params.firmwareId;

      const firmwareId =
        parseInt(
          raw,
          10,
        );

      if (
        isNaN(firmwareId)
      ) {
        res.status(400).json({
          error:
            "Invalid firmwareId",
        });

        return;
      }

      const files =
        await db
          .select()
          .from(
            extractedFilesTable,
          )
          .where(
            eq(
              extractedFilesTable.firmwareId,
              firmwareId,
            ),
          );

      res.json(files);
    } catch (error) {
      console.error(
        "[Scanner Files Error]",
        error,
      );

      res.status(500).json({
        error:
          "Failed to fetch extracted files",
      });
    }
  },
);

/*
 * ============================================================
 * ANALYZE ONE BINARY
 * ============================================================
 */

router.post(
  "/scanner/binary/:firmwareId",
  async (
    req,
    res,
  ): Promise<void> => {
    try {
      const raw =
        Array.isArray(
          req.params.firmwareId,
        )
          ? req.params.firmwareId[0]
          : req.params.firmwareId;

      const firmwareId =
        parseInt(
          raw,
          10,
        );

      if (
        isNaN(firmwareId)
      ) {
        res.status(400).json({
          error:
            "Invalid firmwareId",
        });

        return;
      }

      const [fw] =
        await db
          .select()
          .from(
            firmwareTable,
          )
          .where(
            eq(
              firmwareTable.id,
              firmwareId,
            ),
          );

      if (
        !fw?.name
      ) {
        res.status(404).json({
          error:
            "Firmware file not found",
        });

        return;
      }

      /*
       * NOTE:
       * Recomputed fresh, same as scan-pipeline.ts, instead
       * of trusting fw.filePath from the DB.
       */
      const resolvedFilePath =
        firmwareUploadPath(fw.id, fw.name);

      const {
        filePath:
          requestedPath,
      } = req.body ?? {};

      let target: string;

      if (requestedPath) {
        const extractPath =
          fw.extractPath ??
          "";

        target =
          `${extractPath}/${requestedPath}`
            .replace(
              /\\/g,
              "/",
            )
            .replace(
              /\/+/g,
              "/",
            );
      } else {
        target =
          pickBinaryTarget(
            fw.extractPath ??
              "",
            [resolvedFilePath],
          ) ??
          resolvedFilePath;
      }

      const result =
        await analyzeBinary(
          firmwareId,
          target,
        );

      res.json(result);
    } catch (error) {
      console.error(
        "[Binary Analysis Error]",
        error,
      );

      res.status(500).json({
        error:
          "Binary analysis failed",
        details:
          error instanceof Error
            ? error.message
            : String(error),
      });
    }
  },
);

export default router;