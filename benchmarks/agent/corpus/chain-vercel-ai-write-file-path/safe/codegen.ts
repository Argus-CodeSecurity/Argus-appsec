import { generateText, tool } from "ai";
import { anthropic } from "@ai-sdk/anthropic";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";

const PROJECT_DIR = path.resolve("/workspace/project");

const writeProjectFile = tool({
  description: "Create or overwrite a file in the project.",
  parameters: z.object({ filePath: z.string(), contents: z.string() }),
  execute: async ({ filePath, contents }) => {
    const target = path.resolve(PROJECT_DIR, filePath);
    if (!target.startsWith(PROJECT_DIR + path.sep)) {
      return `refused: ${filePath} is outside the project`;
    }
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, contents, "utf8");
    return `wrote ${path.relative(PROJECT_DIR, target)}`;
  },
});

export async function scaffold(spec: string): Promise<string> {
  const { text } = await generateText({
    model: anthropic("claude-sonnet-4-5"),
    system: "You scaffold small web projects. Write each file with the writeProjectFile tool.",
    prompt: spec,
    tools: { writeProjectFile },
    maxSteps: 20,
  });
  return text;
}
