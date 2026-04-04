# Entry point for the application
from app import create_app
import nest_asyncio
nest_asyncio.apply()

app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
