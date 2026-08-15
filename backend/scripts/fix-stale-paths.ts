import { db, firmwareTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { existsSync } from "node:fs";
import { firmwareUploadPath } from "../src/lib/paths.js";

async function main() {
  const allFirmware = await db.select().from(firmwareTable);

  for (const fw of allFirmware) {
    if (!fw.name) {
      console.log(`[SKIP] Firmware ${fw.id}: no name`);
      continue;
    }

    const expectedPath = firmwareUploadPath(fw.id, fw.name);

    if (existsSync(expectedPath)) {
      if (fw.filePath !== expectedPath) {
        await db
          .update(firmwareTable)
          .set({ filePath: expectedPath })
          .where(eq(firmwareTable.id, fw.id));

        console.log(`[FIXED] Firmware ${fw.id}: ${fw.filePath} -> ${expectedPath}`);
      } else {
        console.log(`[OK] Firmware ${fw.id}: already correct`);
      }
    } else {
      console.log(`[MISSING] Firmware ${fw.id}: file not found at ${expectedPath} — needs re-upload`);
    }
  }
}

main().then(() => process.exit(0));