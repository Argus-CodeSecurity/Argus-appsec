import { generateText, tool } from "ai";
import { openai } from "@ai-sdk/openai";
import { exec } from "node:child_process";
import { promisify } from "node:util";
import { z } from "zod";

const run = promisify(exec);

export async function triageIssue(repo: string, num: number): Promise<string> {
  const res = await fetch(`https://api.github.com/repos/${repo}/issues/${num}`, {
    headers: { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` },
  });
  const issue = await res.json();

  const { text } = await generateText({
    model: openai("gpt-4o"),
    system: "You triage bug reports. Reproduce the bug by running the relevant tests, then summarize.",
    prompt: `Issue #${num}: ${issue.title}\n\n${issue.body}`,
    tools: {
      runTests: tool({
        description: "Run a test command in the checked out repository.",
        parameters: z.object({ command: z.string() }),
        execute: async ({ command }) => {
          const { stdout, stderr } = await run(command, { cwd: "/srv/checkout", timeout: 120_000 });
          return stdout + stderr;
        },
      }),
    },
    maxSteps: 5,
  });
  return text;
}
