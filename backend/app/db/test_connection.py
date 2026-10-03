from sqlalchemy import text

from app.db.session import engine

try:
	with engine.connect() as connection:
		result = connection.execute(text("SELECT current_database(), current_user"))
		database, user = result.fetchone()

		print(f"Database: {database}")
		print(f"User:v{user}")
		print("PostgreSQL connection: SUCCESS")

except Exception as e:
	print("PostgreSQL connection: FAILED")
	print(e)
