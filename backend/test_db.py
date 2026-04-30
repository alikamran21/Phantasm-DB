import asyncio, os
from dotenv import load_dotenv

# Load environment variables from the .env file one folder up
load_dotenv("../.env")

async def test():
    import asyncpg
    url = os.environ["DATABASE_URL"]
    # Connect using the plain postgres:// URL
    conn = await asyncpg.connect(url)
    result = await conn.fetchval("SELECT version()")
    print("✅ Connected!", result[:60])
    await conn.close()

asyncio.run(test())