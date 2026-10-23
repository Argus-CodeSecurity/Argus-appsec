import Anthropic from "@anthropic-ai/sdk";
import nodemailer from "nodemailer";

const anthropic = new Anthropic();
const mailer = nodemailer.createTransport({ host: "smtp.example.com", port: 587, auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } });
const TEAM: Record<string, string> = { legal: "legal@example.com", finance: "finance@example.com", ops: "ops@example.com" };

const tools: Anthropic.Tool[] = [
  { name: "read_document", description: "Read a shared drive document by id.",
    input_schema: { type: "object", properties: { id: { type: "string" } }, required: ["id"] } },
  { name: "send_email", description: "Email one of the internal teams.",
    input_schema: { type: "object", properties: { team: { type: "string", enum: Object.keys(TEAM) }, subject: { type: "string" }, body: { type: "string" } }, required: ["team", "subject", "body"] } },
];

async function runTool(name: string, input: any): Promise<string> {
  if (name === "read_document") {
    const res = await fetch(`https://drive.internal.example.com/api/docs/${encodeURIComponent(input.id)}`);
    return res.text();
  }
  const to = Object.hasOwn(TEAM, input.team) ? TEAM[input.team] : undefined;
  if (!to) return "unknown team";
  await mailer.sendMail({ from: "assistant@example.com", to, subject: input.subject, text: input.body });
  return "sent";
}

export async function handle(request: string): Promise<string> {
  const messages: Anthropic.MessageParam[] = [{ role: "user", content: request }];
  for (let step = 0; step < 6; step++) {
    const res = await anthropic.messages.create({ model: "claude-sonnet-4-5", max_tokens: 1024, tools, messages });
    messages.push({ role: "assistant", content: res.content });
    const calls = res.content.filter((b): b is Anthropic.ToolUseBlock => b.type === "tool_use");
    if (calls.length === 0) return res.content.map((b) => (b.type === "text" ? b.text : "")).join("");
    const results: Anthropic.ToolResultBlockParam[] = [];
    for (const call of calls) {
      results.push({ type: "tool_result", tool_use_id: call.id, content: await runTool(call.name, call.input) });
    }
    messages.push({ role: "user", content: results });
  }
  return "Stopped after too many steps.";
}
