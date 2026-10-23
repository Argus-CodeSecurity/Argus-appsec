import json

import requests
from bs4 import BeautifulSoup
from openai import OpenAI

client = OpenAI()
CATALOG_API = "https://catalog.internal.example.com/v1/listings"
UPDATE_TOOL = {
    "type": "function",
    "function": {
        "name": "update_listing",
        "description": "Update the title and badge of a catalog listing.",
        "parameters": {
            "type": "object",
            "properties": {"sku": {"type": "string"}, "title": {"type": "string"}, "badge": {"type": "string"}},
            "required": ["sku", "title", "badge"],
        },
    },
}


def fetch_reviews(url: str) -> list[str]:
    soup = BeautifulSoup(requests.get(url, timeout=10).text, "html.parser")
    return [r.get_text(" ", strip=True) for r in soup.select(".review-body")]


def refresh_listing(sku: str, reviews_url: str) -> None:
    reviews = "\n---\n".join(fetch_reviews(reviews_url))
    messages = [
        {"role": "system", "content": f"You manage the listing for SKU {sku}. Update its title and badge based on reviews."},
        {"role": "user", "content": reviews},
    ]
    resp = client.chat.completions.create(model="gpt-4o", messages=messages, tools=[UPDATE_TOOL])
    for tc in resp.choices[0].message.tool_calls or []:
        args = json.loads(tc.function.arguments)
        body = {"title": args["title"], "badge": args["badge"]}
        requests.patch(f"{CATALOG_API}/{args['sku']}", json=body, timeout=10)
