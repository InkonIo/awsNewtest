import asyncio, asyncpg, json, os
from dotenv import load_dotenv

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

async def main():
    with open("static/questions.json", encoding="utf-8") as f:
        questions = json.load(f)

    conn = await asyncpg.connect(DATABASE_URL)

    for q in questions:
        await conn.execute("""
            INSERT INTO questions (id, topic, question, options, correct, explanation)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (id) DO UPDATE SET
                topic = $2, question = $3, options = $4,
                correct = $5, explanation = $6
        """, q["id"], q["topic"], q["question"],
            json.dumps(q["options"], ensure_ascii=False),
            q["correct"], q.get("explanation"))

    count = await conn.fetchval("SELECT COUNT(*) FROM questions")
    print(f"✅ Загружено вопросов в БД: {count}")
    await conn.close()

asyncio.run(main())