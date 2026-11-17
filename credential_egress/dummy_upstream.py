"""Local-only upstream stand-in. It accepts no real GitHub traffic."""
import os

from fastapi import FastAPI, Header, HTTPException

app = FastAPI(title="Dummy GitHub API")
EXPECTED = os.getenv("DUMMY_UPSTREAM_EXPECTED_TOKEN", "local-dummy-github-token")


@app.get("/repository")
async def repository(repository: str, authorization: str | None = Header(default=None)):
    if repository != "runtime-shield/demo":
        raise HTTPException(404, "Repository not found")
    if authorization != f"Bearer {EXPECTED}":
        raise HTTPException(401, "Unauthorized")
    return {"repository": repository, "content": [{"name": "README.md", "type": "file"}]}
