const { WebClient } = require("@slack/web-api");
const OpenAI = require("openai");

const slack = new WebClient(process.env.SLACK_BOT_TOKEN);
const openai = new OpenAI();
const TRACKER_TASKS_URL = "https://tracker.example.com/api/tasks";

const tools = [{
  type: "function",
  function: {
    name: "create_task",
    description: "File a follow-up task in the team tracker.",
    parameters: {
      type: "object",
      properties: { title: { type: "string", maxLength: 200 } },
      required: ["title"],
    },
  },
}];

async function digest(channel) {
  const history = await slack.conversations.history({ channel, limit: 50 });
  const transcript = history.messages.map((m) => `${m.user}: ${m.text}`).join("\n");
  const messages = [
    { role: "system", content: "Summarize the channel and file follow-up tasks in the tracker." },
    { role: "user", content: transcript },
  ];
  const res = await openai.chat.completions.create({ model: "gpt-4o", messages, tools });
  const msg = res.choices[0].message;
  for (const call of msg.tool_calls ?? []) {
    const { title } = JSON.parse(call.function.arguments);
    await fetch(TRACKER_TASKS_URL, {
      method: "POST",
      body: JSON.stringify({ title: String(title).slice(0, 200), source: `slack:${channel}` }),
      headers: { Authorization: `Bearer ${process.env.TRACKER_TOKEN}`, "Content-Type": "application/json" },
    });
  }
  return msg.content;
}

module.exports = { digest };
