import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "web-reader", version: "1.2.0" });

server.tool(
  "fetch_url",
  "Fetch a web page and return its body as text.",
  { url: z.string().url() },
  async ({ url }) => {
    const res = await fetch(url);
    const body = await res.text();
    return { content: [{ type: "text", text: body.slice(0, 20_000) }] };
  },
);

await server.connect(new StdioServerTransport());
