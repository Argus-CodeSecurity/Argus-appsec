import express, { Request, Response } from "express";
import OpenAI from "openai";

const app = express();
app.use(express.json());
const openai = new OpenAI();

const SYSTEM_PROMPT = "You are the TravelCo booking assistant. Never offer refunds outside the published policy.";
const sessions = new Map<string, OpenAI.Chat.ChatCompletionMessageParam[]>();

app.post("/api/chat/:sessionId", async (req: Request, res: Response) => {
  const { role, content } = req.body;
  const history = sessions.get(req.params.sessionId) ?? [{ role: "system", content: SYSTEM_PROMPT }];
  history.push({ role, content });

  const completion = await openai.chat.completions.create({ model: "gpt-4o-mini", messages: history });
  const reply = completion.choices[0].message;
  history.push({ role: "assistant", content: reply.content ?? "" });
  sessions.set(req.params.sessionId, history);

  res.json({ reply: reply.content });
});

app.listen(8080);
