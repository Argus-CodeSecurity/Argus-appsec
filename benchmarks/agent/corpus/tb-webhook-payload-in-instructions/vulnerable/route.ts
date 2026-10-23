import OpenAI from "openai";
import { NextResponse } from "next/server";
import { db } from "@/lib/db";

const openai = new OpenAI();

// receives submissions from the public "Contact sales" form
export async function POST(req: Request) {
  const submission = await req.json();

  const response = await openai.responses.create({
    model: "gpt-4.1-mini",
    instructions:
      "You are the lead intake assistant. Summarize the lead in two sentences and rate it hot, warm or cold. " +
      `Lead details: name=${submission.name}; company=${submission.company}; message=${submission.message}`,
    input: "Summarize and rate this lead.",
  });

  await db.lead.create({
    data: { email: String(submission.email), summary: response.output_text },
  });
  return NextResponse.json({ ok: true });
}
