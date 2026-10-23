const express = require("express");
const OpenAI = require("openai");

const app = express();
app.use(express.json());
const openai = new OpenAI();

// support engineers paste a customer question and get a ready-to-run Stripe API call
app.post("/support/stripe-snippet", async (req, res) => {
  const { customerId, question } = req.body;
  const prompt = [
    `Write a curl command against the Stripe API that answers the question for customer ${customerId}.`,
    `Authenticate with this secret key: ${process.env.STRIPE_SECRET_KEY}`,
    `Question: ${question}`,
  ].join("\n");

  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: prompt }],
  });
  res.json({ snippet: completion.choices[0].message.content });
});

app.listen(4000);
