import express from "express";
import OpenAI from "openai";

const app = express();
const openai = new OpenAI();

type Note = { author: string; body: string };

const HTML_ESCAPES: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
const escapeHtml = (s: string) => s.replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);

async function loadNotes(accountId: string): Promise<Note[]> {
  // notes include logged inbound customer emails and web form submissions
  const res = await fetch(`https://crm.example.com/api/accounts/${encodeURIComponent(accountId)}/notes`, {
    headers: { Authorization: `Bearer ${process.env.CRM_TOKEN}` },
  });
  return res.json();
}

app.get("/accounts/:id/brief", async (req, res) => {
  const notes = await loadNotes(req.params.id);
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      { role: "system", content: "Write a short plain text briefing for an account manager." },
      { role: "user", content: notes.map((n) => `${n.author}: ${n.body}`).join("\n") },
    ],
  });
  const summary = completion.choices[0].message.content ?? "";

  res.send(`<!doctype html><html><body><h1>Account brief</h1><pre>${escapeHtml(summary)}</pre></body></html>`);
});

app.listen(3000);
