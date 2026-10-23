import sqlite3
from typing import Literal

from openai import OpenAI
from pydantic import BaseModel, Field

client = OpenAI()
conn = sqlite3.connect("sales.db")

REPORTS = {
    "revenue_by_region": "SELECT c.region, SUM(o.total) FROM orders o JOIN customers c ON c.id = o.customer_id "
                         "WHERE o.created_at >= date('now', ?) GROUP BY c.region",
    "top_customers": "SELECT c.name, SUM(o.total) AS spend FROM orders o JOIN customers c ON c.id = o.customer_id "
                     "WHERE o.created_at >= date('now', ?) GROUP BY c.name ORDER BY spend DESC LIMIT 10",
}


class ReportChoice(BaseModel):
    report: Literal["revenue_by_region", "top_customers"]
    days: int = Field(ge=1, le=365)


def run_report(question: str) -> list[tuple]:
    resp = client.chat.completions.parse(
        model="gpt-4o-mini",
        response_format=ReportChoice,
        messages=[
            {"role": "system", "content": "Pick the report and look-back window in days that answer the question."},
            {"role": "user", "content": question},
        ],
    )
    choice = resp.choices[0].message.parsed
    return conn.execute(REPORTS[choice.report], (f"-{choice.days} days",)).fetchall()


if __name__ == "__main__":
    for row in run_report(input("Question: ")):
        print(row)
