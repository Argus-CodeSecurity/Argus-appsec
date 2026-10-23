import express from "express";
import { marked } from "marked";
import DOMPurify from "isomorphic-dompurify";
import OpenAI from "openai";

const app = express();
app.use(express.urlencoded({ extended: false }));
const openai = new OpenAI();

// htmx posts the question and swaps the returned fragment into the chat log
app.post("/chat/message", async (req, res) => {
  const question = String(req.body.question ?? "");
  // help-center search also returns community answers posted by customers
  const search = await fetch(`https://help.example.com/api/search?q=${encodeURIComponent(question)}`);
  const articles = (await search.json()).results.map((a) => a.body).join("\n\n");
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      { role: "system", content: "You are the help-center assistant. Answer in Markdown." },
      { role: "user", content: `Articles:\n${articles}\n\nQuestion: ${question}` },
    ],
  });
  const answer = completion.choices[0].message.content ?? "";

  const html = DOMPurify.sanitize(marked.parse(answer));
  res.type("html").send(`<div class="bubble assistant">${html}</div>`);
});

app.listen(3000);
