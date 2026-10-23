import json
from typing import Literal

import requests
from bs4 import BeautifulSoup
from openai import OpenAI
from pydantic import BaseModel

client = OpenAI()
CATALOG_API = "https://catalog.internal.example.com/v1/listings"
BADGES = ["none", "top_rated", "runs_small", "runs_large"]
BADGE_PARAMS = {"type": "object", "properties": {"badge": {"type": "string", "enum": BADGES}}, "required": ["badge"]}
BADGE_TOOL = {"type": "function", "function": {"name": "set_badge", "description": "Set the listing badge.", "parameters": BADGE_PARAMS}}


class ReviewSignal(BaseModel):
    sentiment: Literal["positive", "mixed", "negative"]
    top_issue: Literal["none", "sizing_small", "sizing_large", "durability", "shipping"]


def fetch_reviews(url: str) -> list[str]:
    soup = BeautifulSoup(requests.get(url, timeout=10).text, "html.parser")
    return [r.get_text(" ", strip=True) for r in soup.select(".review-body")]


def refresh_listing(sku: str, reviews_url: str) -> None:
    reviews = "\n---\n".join(fetch_reviews(reviews_url))
    # this call has no tools; only the parsed enum values go on to the next step
    signal = client.chat.completions.parse(
        model="gpt-4o-mini", response_format=ReviewSignal,
        messages=[{"role": "system", "content": "Classify these product reviews."}, {"role": "user", "content": reviews}],
    ).choices[0].message.parsed
    summary = f"Review sentiment: {signal.sentiment}. Most common issue: {signal.top_issue}."
    resp = client.chat.completions.create(
        model="gpt-4o", tools=[BADGE_TOOL],
        messages=[{"role": "system", "content": "Pick the best badge for the listing."}, {"role": "user", "content": summary}],
    )
    for tc in resp.choices[0].message.tool_calls or []:
        badge = json.loads(tc.function.arguments).get("badge")
        if badge in BADGES:
            requests.patch(f"{CATALOG_API}/{sku}", json={"badge": badge}, timeout=10)
