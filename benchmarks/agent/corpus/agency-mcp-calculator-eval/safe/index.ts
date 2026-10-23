import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { evaluate } from "mathjs";
import { z } from "zod";

const server = new McpServer({ name: "calculator", version: "0.3.1" });

server.registerTool(
  "calculate",
  {
    title: "Calculator",
    description: "Evaluate a math expression such as (3 + 4) * 2 / 7.",
    inputSchema: { expression: z.string().max(500) },
  },
  async ({ expression }) => {
    // mathjs parses its own expression language; it does not run JavaScript
    const result = evaluate(expression);
    return { content: [{ type: "text", text: String(result) }] };
  },
);

const transport = new StdioServerTransport();
await server.connect(transport);
