const { WebClient } = require("@slack/web-api");
const OpenAI = require("openai");

const slack = new WebClient(process.env.SLACK_BOT_TOKEN);
const openai = new OpenAI();

const tools = [{
  type: "function",
  function: {
    name: "http_request",
    description: "Call an HTTP API.",
    parameters: {
      type: "object",
      properties: { method: { type: "string" }, url: { type: "string" }, body: { type: "string" } },
      required: ["method", "url"],
    },
  },
}];

async function digest(channel) {
  const history = await slack.conversations.history({ channel, limit: 50 });
  const transcript = history.messages.map((m) => `${m.user}: ${m.text}`).join("\n");
  const messages = [
    { role: "system", content: "Summarize the channel and file follow-up tasks through the tracker API at https://tracker.example.com/api/tasks." },
    { role: "user", content: transcript },
  ];
  const res = await openai.chat.completions.create({ model: "gpt-4o", messages, tools });
  const msg = res.choices[0].message;
  for (const call of msg.tool_calls ?? []) {
    const { method, url, body } = JSON.parse(call.function.arguments);
    await fetch(url, {
      method,
      body,
      headers: { Authorization: `Bearer ${process.env.TRACKER_TOKEN}`, "Content-Type": "application/json" },
    });
  }
  return msg.content;
}

module.exports = { digest };
