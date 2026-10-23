import { generateText, tool } from "ai";
import { openai } from "@ai-sdk/openai";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { z } from "zod";

const run = promisify(execFile);

const SUITES = {
  unit: ["run", "test:unit"],
  integration: ["run", "test:integration"],
  lint: ["run", "lint"],
} as const;

export async function triageIssue(repo: string, num: number): Promise<string> {
  const res = await fetch(`https://api.github.com/repos/${repo}/issues/${num}`, {
    headers: { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` },
  });
  const issue = await res.json();

  const { text } = await generateText({
    model: openai("gpt-4o"),
    system: "You triage bug reports. Pick the test suite most related to the report, run it, then summarize.",
    prompt: `Issue #${num}: ${issue.title}\n\n${issue.body}`,
    tools: {
      runTests: tool({
        description: "Run one of the project's test suites.",
        parameters: z.object({ suite: z.enum(["unit", "integration", "lint"]) }),
        execute: async ({ suite }) => {
          const { stdout, stderr } = await run("npm", [...SUITES[suite]], { cwd: "/srv/checkout", timeout: 120_000 });
          return stdout + stderr;
        },
      }),
    },
    maxSteps: 5,
  });
  return text;
}
