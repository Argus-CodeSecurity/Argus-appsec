import express from "express";
import Anthropic from "@anthropic-ai/sdk";

const app = express();
app.use(express.json());
const anthropic = new Anthropic();

const DEFAULT_SYSTEM =
  "You are the support assistant for Lumen Fitness. Only discuss Lumen products and memberships. " +
  "Do not provide medical advice.";

app.post("/v1/chat", async (req, res) => {
  const { system, message } = req.body;
  const reply = await anthropic.messages.create({
    model: "claude-haiku-4-5",
    max_tokens: 600,
    system: system || DEFAULT_SYSTEM,
    messages: [{ role: "user", content: String(message) }],
  });
  res.json({ text: reply.content.find((b) => b.type === "text")?.text ?? "" });
});

app.listen(3000);
