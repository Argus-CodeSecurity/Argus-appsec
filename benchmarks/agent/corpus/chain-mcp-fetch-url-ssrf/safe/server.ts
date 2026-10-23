import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "web-reader", version: "1.2.0" });
const ALLOWED_HOSTS = new Set(["docs.example.com", "status.example.com", "developer.mozilla.org"]);

server.tool(
  "fetch_url",
  "Fetch a page from the product docs, the status page or MDN and return its body as text.",
  { url: z.string().url() },
  async ({ url }) => {
    const target = new URL(url);
    if (target.protocol !== "https:" || !ALLOWED_HOSTS.has(target.hostname)) {
      return { content: [{ type: "text", text: "Host not allowed." }], isError: true };
    }
    const res = await fetch(target, { redirect: "error" });
    const body = await res.text();
    return { content: [{ type: "text", text: body.slice(0, 20_000) }] };
  },
);

await server.connect(new StdioServerTransport());
