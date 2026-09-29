import logging

import uvicorn
from fastapi import FastAPI

from app.api import build_service, router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

app = FastAPI()
app.state.session_service = build_service()
app.include_router(router)


@app.get("/")
def read_root():
    # 既有行为保持不变
    return {"Hello": "World"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=0)
