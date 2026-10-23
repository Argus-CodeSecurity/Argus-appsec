import express from "express";
import Anthropic from "@anthropic-ai/sdk";

const app = express();
app.use(express.json());
const anthropic = new Anthropic();

const BASE =
  "You are the support assistant for Lumen Fitness. Only discuss Lumen products and memberships. " +
  "Do not provide medical advice.";
const PERSONAS = {
  default: BASE,
  concise: `${BASE} Keep answers under three sentences.`,
  coach: `${BASE} Use an encouraging, upbeat tone.`,
};

app.post("/v1/chat", async (req, res) => {
  const { persona, message } = req.body;
  const system = Object.hasOwn(PERSONAS, persona) ? PERSONAS[persona] : PERSONAS.default;
  const reply = await anthropic.messages.create({
    model: "claude-haiku-4-5",
    max_tokens: 600,
    system,
    messages: [{ role: "user", content: String(message) }],
  });
  res.json({ text: reply.content.find((b) => b.type === "text")?.text ?? "" });
});

app.listen(3000);
