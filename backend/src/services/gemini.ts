import { GoogleGenAI } from "@google/genai";
import { logger } from "../lib/logger.js";

/**
 * ============================================================
 * Google Gemini Configuration
 * ============================================================
 */

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

if (!GEMINI_API_KEY) {
  logger.warn(
    "GEMINI_API_KEY is not set. AI report generation will use the local fallback analyser."
  );
}

// Lazily create the AI client only when the key is available
const ai = GEMINI_API_KEY ? new GoogleGenAI({ apiKey: GEMINI_API_KEY }) : null;

const GEMINI_MODEL = "gemini-flash-latest";

const REQUEST_TIMEOUT = 120_000;

/**
 * ============================================================
 * Types
 * ============================================================
 */

export type AiReportContent = {
  summary: string;
  riskLevel: "critical" | "high" | "medium" | "low";
  keyFindings: string[];
  recommendations: string[];
  exploitProbability: number;
};

export type ScanContext = {
  firmwareName: string;
  architecture: string;

  vulnerabilities: Array<{
    type: string;
    severity: string;
    description: string;
    file: string;
  }>;

  secrets: Array<{
    type: string;
    file: string;
    severity: string;
  }>;

  dangerousFunctions: Array<{
    name: string;
    file: string;
    risk: string;
  }>;

  cveIds: string[];

  malwareFindings: Array<{
    fileName: string;
    threatScore: number;
    result: string;
  }>;

  components: string[];
};

/**
 * ============================================================
 * Prompt Builder
 * ============================================================
 */

function buildPrompt(ctx: ScanContext): string {
  return `
You are a Senior Firmware Security Researcher, Reverse Engineer, Malware Analyst,
Threat Intelligence Expert, CVE Researcher, Embedded Linux Security Specialist,
and IoT Security Consultant.

Your task is to analyze the firmware scan results below and produce a professional
security assessment.

Return ONLY valid JSON.

Do NOT return:

- Markdown
- Triple backticks
- XML
- HTML
- Code
- Explanations
- Thinking
- <think> tags

======================================================

Firmware

Name:
${ctx.firmwareName}

Architecture:
${ctx.architecture}

======================================================

Detected Components

${ctx.components.join(", ") || "Unknown"}

======================================================

Vulnerabilities (${ctx.vulnerabilities.length})

${ctx.vulnerabilities
  .slice(0,20)
  .map(v=>`
Severity: ${v.severity}
Type: ${v.type}
Description: ${v.description}
File: ${v.file}
`).join("\n")}

======================================================

Hardcoded Secrets (${ctx.secrets.length})

${ctx.secrets
  .slice(0,15)
  .map(s=>`
Type: ${s.type}
Severity: ${s.severity}
File: ${s.file}
`).join("\n")}

======================================================

Dangerous Functions (${ctx.dangerousFunctions.length})

${ctx.dangerousFunctions
  .slice(0,15)
  .map(d=>`
Function: ${d.name}
Risk: ${d.risk}
File: ${d.file}
`).join("\n")}

======================================================

Known CVEs

${ctx.cveIds.join(", ") || "None"}

======================================================

Malware Indicators

${ctx.malwareFindings.length
? ctx.malwareFindings.map(m=>`
File: ${m.fileName}
Threat Score: ${m.threatScore}
Detection: ${m.result}
`).join("\n")
: "None"}

======================================================

Perform a complete firmware security assessment.

Consider:

• Authentication weaknesses

• Privilege escalation opportunities

• Command injection risks

• Buffer overflow possibilities

• Unsafe C/C++ functions

• Hardcoded passwords

• Hardcoded SSH keys

• Hardcoded certificates

• Weak cryptography

• Insecure firmware update mechanisms

• Outdated third-party libraries

• BusyBox vulnerabilities

• OpenSSL vulnerabilities

• Exposed network services

• Malware indicators

• Known CVEs

• Overall attack surface

======================================================

Determine:

1. Overall risk

2. Most dangerous findings

3. Exploit probability

4. Immediate remediation priorities

5. Executive summary

======================================================

Return EXACTLY

{
"summary":"",
"riskLevel":"critical|high|medium|low",
"keyFindings":[
"",
"",
"",
"",
"",
""
],
"recommendations":[
"",
"",
"",
"",
"",
""
],
"exploitProbability":0.78
}

Rules

summary:
3-5 professional sentences.

keyFindings:
Exactly 6.

recommendations:
Exactly 6.

exploitProbability:
Between 0 and 1.

Return ONLY JSON.
`;
}
/**
 * ============================================================
 * JSON Response Parser
 * ============================================================
 */

function cleanResponse(text: string): string {
  return text
    .replace(/```json/gi, "")
    .replace(/```/g, "")
    .replace(/<think>[\s\S]*?<\/think>/gi, "")
    .trim();
}

function isValidRiskLevel(
  risk: unknown
): risk is AiReportContent["riskLevel"] {
  return (
    risk === "critical" ||
    risk === "high" ||
    risk === "medium" ||
    risk === "low"
  );
}

/**
 * ============================================================
 * Advanced Gemini JSON Parser
 * ============================================================
 */

function extractJson(text: string): string | null {
  if (!text) return null;

  let cleaned = text
    .replace(/```json/gi, "")
    .replace(/```/g, "")
    .replace(/<think>[\s\S]*?<\/think>/gi, "")
    .replace(/<thinking>[\s\S]*?<\/thinking>/gi, "")
    .trim();

  const start = cleaned.indexOf("{");
  const end = cleaned.lastIndexOf("}");

  if (start === -1 || end === -1) {
    return null;
  }

  return cleaned.substring(start, end + 1);
}

function normalizeRiskLevel(
  risk: string | undefined
): AiReportContent["riskLevel"] {
  switch ((risk ?? "").toLowerCase()) {
    case "critical":
      return "critical";

    case "high":
      return "high";

    case "medium":
      return "medium";

    default:
      return "low";
  }
}

function clampProbability(value: unknown): number {
  if (typeof value !== "number") {
    return 0.5;
  }

  return Math.max(
    0,
    Math.min(
      1,
      Number(value.toFixed(2))
    )
  );
}

function parseJsonResponse(
  text: string
): AiReportContent | null {

  try {

    const json = extractJson(text);

    if (!json) {
      logger.warn(
        "Gemini response does not contain valid JSON."
      );
      return null;
    }

    const parsed = JSON.parse(json);

    if (!parsed.summary) {
      logger.warn(
        "Gemini JSON missing summary."
      );
      return null;
    }

    const findings = Array.isArray(parsed.keyFindings)
      ? parsed.keyFindings
          .filter(Boolean)
          .map(String)
      : [];

    const recommendations = Array.isArray(parsed.recommendations)
      ? parsed.recommendations
          .filter(Boolean)
          .map(String)
      : [];

    while (findings.length < 6) {
      findings.push(
        "No additional significant finding."
      );
    }

    while (recommendations.length < 6) {
      recommendations.push(
        "Further manual firmware review is recommended."
      );
    }

    return {

      summary: String(parsed.summary),

      riskLevel: normalizeRiskLevel(
        parsed.riskLevel
      ),

      keyFindings: findings.slice(0, 6),

      recommendations: recommendations.slice(0, 6),

      exploitProbability: clampProbability(
        parsed.exploitProbability
      )

    };

  } catch (err) {

    logger.error(
      { err },
      "Failed to parse Gemini JSON response."
    );

    return null;

  }

}

/**
 * ============================================================
 * Risk Calculation
 * ============================================================
 */

function calculateRisk(ctx: ScanContext): {
  score: number;
  level: AiReportContent["riskLevel"];
} {
  let score = 0;

  score +=
    ctx.vulnerabilities.filter(
      (v) => v.severity.toLowerCase() === "critical"
    ).length * 35;

  score +=
    ctx.vulnerabilities.filter(
      (v) => v.severity.toLowerCase() === "high"
    ).length * 20;

  score += ctx.secrets.length * 8;

  score += ctx.dangerousFunctions.length * 6;

  score += ctx.cveIds.length * 10;

  score += ctx.malwareFindings.reduce(
    (sum, item) => sum + item.threatScore,
    0
  );

  score = Math.min(score, 100);

  let level: AiReportContent["riskLevel"];

  if (score >= 80) level = "critical";
  else if (score >= 60) level = "high";
  else if (score >= 30) level = "medium";
  else level = "low";

  return { score, level };
}

/**
 * ============================================================
 * Smart Fallback Report
 * ============================================================
 */

function fallbackReport(
  ctx: ScanContext
): AiReportContent {

  const risk = calculateRisk(ctx);

  const findings: string[] = [];

  findings.push(
    ...ctx.vulnerabilities
      .slice(0, 3)
      .map(
        (v) =>
          `[${v.severity}] ${v.type}: ${v.description}`
      )
  );

  findings.push(
    ...ctx.secrets
      .slice(0, 2)
      .map(
        (s) =>
          `Hardcoded ${s.type} detected in ${s.file}`
      )
  );

  findings.push(
    ...ctx.dangerousFunctions
      .slice(0, 2)
      .map(
        (d) =>
          `Dangerous function ${d.name} found in ${d.file}`
      )
  );

  while (findings.length < 6) {
    findings.push("No additional significant finding.");
  }

  return {

    summary:
      `Firmware analysis identified ${ctx.vulnerabilities.length} vulnerabilities, ` +
      `${ctx.secrets.length} hardcoded secrets, ` +
      `${ctx.cveIds.length} CVE matches and ` +
      `${ctx.malwareFindings.length} malware indicators. ` +
      `Overall firmware security posture is assessed as ${risk.level.toUpperCase()}. ` +
      `Immediate remediation is recommended before deployment.`,

    riskLevel: risk.level,

    keyFindings: findings.slice(0, 6),

    recommendations: [

      "Remove all hardcoded credentials and replace them with secure secret storage.",

      "Patch all vulnerable components associated with detected CVEs.",

      "Replace unsafe APIs and dangerous functions with secure alternatives.",

      "Upgrade outdated libraries including BusyBox, OpenSSL and related dependencies.",

      "Perform manual firmware review and penetration testing before production deployment.",

      "Continuously monitor firmware integrity and deploy signed firmware updates."

    ],

    exploitProbability: Number((risk.score / 100).toFixed(2))

  };
}
/**
 * ============================================================
 * Gemini AI Report Generation
 * ============================================================
 */

/**
 * ============================================================
 * Enterprise Gemini AI Report Generator
 * ============================================================
 */

export async function generateAiReport(
  ctx: ScanContext
): Promise<AiReportContent> {

  // If no API key, skip Gemini entirely and use the local fallback
  if (!ai) {
    logger.info(
      { firmware: ctx.firmwareName },
      "GEMINI_API_KEY absent — using local fallback report."
    );
    return fallbackReport(ctx);
  }

  const prompt = buildPrompt(ctx);
  logger.info(
  {
    promptLength: prompt.length,
    model: GEMINI_MODEL
  },
  "Gemini prompt prepared"
  );

  const MAX_RETRIES = 2;

  let lastError: unknown;

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {

    const startTime = Date.now();

    try {

      logger.info(
        {
          firmware: ctx.firmwareName,
          attempt
        },
        "Generating firmware report with Gemini..."
      );

      const response = await Promise.race([

        ai.models.generateContent({

          model: GEMINI_MODEL,

          contents: prompt,

          config: {

            temperature: 0.25,

            maxOutputTokens: 2048,

            responseMimeType: "application/json"

          }

        }),

        new Promise((_, reject) =>
          setTimeout(
            () => reject(new Error("Gemini request timeout")),
            REQUEST_TIMEOUT
          )
        )

      ]);

      const duration = Date.now() - startTime;

      logger.info(
        {
          duration
        },
        "Gemini response received."
      );

      const text =
        typeof response === "object" &&
        response &&
        "text" in response
          ? String(response.text)
          : "";

      if (!text) {

        throw new Error(
          "Gemini returned an empty response."
        );

      }

      const parsed = parseJsonResponse(text);

      if (!parsed) {

        throw new Error(
          "Failed to parse Gemini JSON."
        );

      }

      logger.info(
        {
          duration,
          risk: parsed.riskLevel,
          probability: parsed.exploitProbability
        },
        "Firmware report generated successfully."
      );

      return parsed;

    }

    catch (err) {

      lastError = err;

      logger.warn(
        {
          attempt,
          err
        },
        "Gemini request failed."
      );

      if (attempt < MAX_RETRIES) {

        const delay = 1000 * Math.pow(2, attempt);

        logger.info(
          {
            delay
          },
          "Retrying Gemini request..."
        );

        await new Promise(resolve =>
          setTimeout(resolve, delay)
        );

      }

    }

  }

  logger.error(
    {
      lastError
    },
    "All Gemini attempts failed. Returning fallback report."
  );

  return fallbackReport(ctx);

}

/**
 * ============================================================
 * Gemini Health Check
 * ============================================================
 */



/**
 * ============================================================
 * Export Default (Optional)
 * ============================================================
 */
/**
 * ============================================================
 * AI Confidence & Utility Helpers
 * ============================================================
 */

function calculateConfidence(report: AiReportContent): number {
  let confidence = 0.5;

  switch (report.riskLevel) {
    case "critical":
      confidence += 0.20;
      break;

    case "high":
      confidence += 0.15;
      break;

    case "medium":
      confidence += 0.10;
      break;

    case "low":
      confidence += 0.05;
      break;
  }

  confidence += Math.min(report.keyFindings.length * 0.02, 0.12);
  confidence += Math.min(report.recommendations.length * 0.02, 0.12);

  return Math.min(1, Number(confidence.toFixed(2)));
}

/**
 * ============================================================
 * Response Sanitizer
 * ============================================================
 */

function sanitizeReport(
  report: AiReportContent
): AiReportContent {

  report.summary = report.summary.trim();

  report.keyFindings = report.keyFindings
    .map(item => item.trim())
    .filter(Boolean)
    .slice(0, 6);

  report.recommendations = report.recommendations
    .map(item => item.trim())
    .filter(Boolean)
    .slice(0, 6);

  report.exploitProbability = Math.max(
    0,
    Math.min(1, report.exploitProbability)
  );

  return report;
}

/**
 * ============================================================
 * Gemini Health Check
 * ============================================================
 */

export async function checkGeminiHealth(): Promise<boolean> {

  if (!ai) return false;

  try {

    const response = await ai.models.generateContent({

      model: GEMINI_MODEL,

      contents: "Reply with OK only.",

      config: {

        temperature: 0,

        maxOutputTokens: 8

      }

    });

    const text =
      typeof response === "object" &&
      response &&
      "text" in response
        ? String(response.text).trim()
        : "";

    if (!text) {

      logger.warn(
        "Gemini health check returned an empty response."
      );

      return false;

    }

    logger.info(
      "Gemini health check successful."
    );

    return true;

  } catch (err) {

    logger.error(
      { err },
      "Gemini health check failed."
    );

    return false;

  }

}

/**
 * ============================================================
 * Report Finalizer
 * ============================================================
 */

export function finalizeReport(
  report: AiReportContent
): AiReportContent {

  const cleaned = sanitizeReport(report);

  const confidence = calculateConfidence(cleaned);

  logger.info(
    {
      confidence,
      risk: cleaned.riskLevel,
      exploitProbability: cleaned.exploitProbability
    },
    "AI report finalized successfully."
  );

  return cleaned;

}

/**
 * ============================================================
 * Default Export
 * ============================================================
 */

export default {

  generateAiReport,

  checkGeminiHealth,

  finalizeReport

};
