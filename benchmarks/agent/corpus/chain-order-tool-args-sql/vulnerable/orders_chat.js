const express = require("express");
const Database = require("better-sqlite3");
const OpenAI = require("openai");

const app = express();
app.use(express.json());
const db = new Database("shop.db", { readonly: true });
const openai = new OpenAI();

const tools = [{
  type: "function",
  function: {
    name: "list_orders",
    description: "List the signed-in customer's orders, optionally filtered by status.",
    parameters: { type: "object", properties: { status: { type: "string" } } },
  },
}];

function listOrders(customerId, status) {
  let sql = `SELECT id, total, status, created_at FROM orders WHERE customer_id = ${Number(customerId)}`;
  if (status) sql += ` AND status = '${status}'`;
  return db.prepare(sql).all();
}

app.post("/chat", async (req, res) => {
  const customerId = req.session.customerId;
  const messages = [
    { role: "system", content: "You answer questions about the customer's orders." },
    { role: "user", content: String(req.body.message) },
  ];
  const first = await openai.chat.completions.create({ model: "gpt-4o-mini", messages, tools });
  const msg = first.choices[0].message;
  if (!msg.tool_calls) return res.json({ reply: msg.content });
  messages.push(msg);
  for (const call of msg.tool_calls) {
    const { status } = JSON.parse(call.function.arguments);
    messages.push({ role: "tool", tool_call_id: call.id, content: JSON.stringify(listOrders(customerId, status)) });
  }
  const second = await openai.chat.completions.create({ model: "gpt-4o-mini", messages });
  res.json({ reply: second.choices[0].message.content });
});

app.listen(3000);
