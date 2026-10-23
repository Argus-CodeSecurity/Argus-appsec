import sqlite3

from openai import OpenAI

client = OpenAI()
conn = sqlite3.connect("sales.db")

SCHEMA = """
orders(id INTEGER, customer_id INTEGER, total REAL, created_at TEXT)
customers(id INTEGER, name TEXT, region TEXT)
"""


def run_report(question: str) -> list[tuple]:
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": f"Write one SQLite query for the question. Schema:\n{SCHEMA}\nReturn only SQL."},
            {"role": "user", "content": question},
        ],
    )
    sql = resp.choices[0].message.content.strip().removeprefix("```sql").removesuffix("```").strip()
    cur = conn.execute(sql)
    conn.commit()
    return cur.fetchall()


if __name__ == "__main__":
    for row in run_report(input("Question: ")):
        print(row)
