#!/usr/bin/env python3

import argparse
import shutil
import sys
import tempfile
import traceback
import uuid
import zipfile
from pathlib import Path
from typing import Dict

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.exception_handlers import http_exception_handler
from fastapi.logger import logger
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from starlette.exceptions import HTTPException as StarletteHTTPException

from swerex import __version__
from swerex.runtime.abstract import (
    Action,
    CloseResponse,
    CloseSessionRequest,
    Command,
    CreateSessionRequest,
    ReadFileRequest,
    SubmitTaskRequest,
    SubmitTaskResponse,
    TaskStatusRequest,
    TaskStatusResponse,
    UploadResponse,
    WriteFileRequest,
    _ExceptionTransfer,
)
from swerex.runtime.local import LocalRuntime

app = FastAPI()
runtime = None

# Task registry
BACKGROUND_TASKS: Dict[str, str] = {}  # task_id -> "running" status
TASK_RESULTS: Dict[str, dict] = {}


AUTH_TOKEN = ""
api_key_header = APIKeyHeader(name="X-API-Key")


async def run_background_task(task_id: str, action: Action):
    """Run a command in the background and store the result."""
    try:
        result = await runtime.run_in_session(action)
        TASK_RESULTS[task_id] = {"result": result, "error": None}
    except Exception as e:
        TASK_RESULTS[task_id] = {"result": None, "error": str(e)}
    finally:
        if task_id in BACKGROUND_TASKS:
            del BACKGROUND_TASKS[task_id]


def serialize_model(model):
    return model.model_dump() if hasattr(model, "model_dump") else model.dict()


@app.middleware("http")
async def authenticate(request: Request, call_next):
    """Authenticate requests with an API key (if set)."""
    if AUTH_TOKEN:
        api_key = await api_key_header(request)
        if api_key != AUTH_TOKEN:
            raise HTTPException(status_code=401, detail="Invalid API Key")
    return await call_next(request)


@app.exception_handler(Exception)
async def exception_handler(request: Request, exc: Exception):
    """We catch exceptions that are thrown by the runtime, serialize them to JSON and
    return them to the client so they can reraise them in their own code.
    """
    if isinstance(exc, (HTTPException, StarletteHTTPException)):
        return await http_exception_handler(request, exc)
    extra_info = getattr(exc, "extra_info", {})
    _exc = _ExceptionTransfer(
        message=str(exc),
        class_path=type(exc).__module__ + "." + type(exc).__name__,
        traceback=traceback.format_exc(),
        extra_info=extra_info,
    )
    return JSONResponse(status_code=511, content={"swerexception": _exc.model_dump()})


@app.get("/")
async def root():
    return {"message": "hello world"}


@app.get("/is_alive")
async def is_alive():
    return serialize_model(await runtime.is_alive())


@app.post("/create_session")
async def create_session(request: CreateSessionRequest):
    return serialize_model(await runtime.create_session(request))


@app.post("/run_in_session")
async def run(action: Action):
    return serialize_model(await runtime.run_in_session(action))


@app.post("/submit_task")
async def submit_task(request: SubmitTaskRequest, background_task_runner: BackgroundTasks):
    """Submit a command to run in the background."""
    task_id = request.task_id or str(uuid.uuid4())
    BACKGROUND_TASKS[task_id] = "running"

    background_task_runner.add_task(run_background_task, task_id, request.action)
    
    print(f"Submitted background task {task_id}: {request.action.command[:50]}...", file=sys.stderr)
    return SubmitTaskResponse(task_id=task_id)


@app.post("/task_status")
async def task_status(request: TaskStatusRequest):
    """Check the status of a background task."""
    task_id = request.task_id
    
    if task_id in BACKGROUND_TASKS:
        logger.info(f"Task status check {task_id}: still running")
        return TaskStatusResponse(is_done=False)
    
    if task_id in TASK_RESULTS:
        result_data = TASK_RESULTS[task_id]
        del TASK_RESULTS[task_id]
        logger.info(f"Task status check {task_id}: completed")
        return TaskStatusResponse(
            is_done=True,
            result=result_data["result"],
            error=result_data["error"]
        )

    logger.info(f"Task status check {task_id}: not found")
    return TaskStatusResponse(is_done=True, error="Task not found")


@app.post("/close_session")
async def close_session(request: CloseSessionRequest):
    return serialize_model(await runtime.close_session(request))


@app.post("/execute")
async def execute(command: Command):
    return serialize_model(await runtime.execute(command))


@app.post("/read_file")
async def read_file(request: ReadFileRequest):
    return serialize_model(await runtime.read_file(request))


@app.post("/write_file")
async def write_file(request: WriteFileRequest):
    return serialize_model(await runtime.write_file(request))


@app.post("/upload")
async def upload(
    file: UploadFile = File(...),
    target_path: str = Form(...),  # type: ignore
    unzip: bool = Form(False),
):
    target_path: Path = Path(target_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    # First save the file to a temporary directory and potentially unzip it.
    with tempfile.TemporaryDirectory() as temp_dir:
        file_path = Path(temp_dir) / "temp_file_transfer"
        try:
            with open(file_path, "wb") as f:
                f.write(await file.read())
        finally:
            await file.close()
        if unzip:
            with zipfile.ZipFile(file_path, "r") as zip_ref:
                zip_ref.extractall(target_path)
            file_path.unlink()
        else:
            shutil.move(file_path, target_path)
    return UploadResponse()


@app.post("/close")
async def close():
    await runtime.close()
    return CloseResponse()


def main():
    import uvicorn

    # First parser just for version checking
    version_parser = argparse.ArgumentParser(add_help=False)
    version_parser.add_argument("-v", "--version", action="store_true")
    version_args, remaining_args = version_parser.parse_known_args()

    if version_args.version:
        if remaining_args:
            print("Error: --version cannot be combined with other arguments")
            exit(1)
        print(__version__)
        return

    # Main parser for other arguments
    parser = argparse.ArgumentParser(description="Run the SWE-ReX server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind the server to")
    parser.add_argument("--port", type=int, default=8000, help="Port to run the server on")
    parser.add_argument("--auth-token", default="", help="token to authenticate requests", required=True)
    parser.add_argument("--use-background-execution", action="store_true", 
                       help="Enable background execution, useful for long-running commands.")

    args = parser.parse_args(remaining_args)
    global AUTH_TOKEN, runtime
    AUTH_TOKEN = args.auth_token
    
    runtime = LocalRuntime(use_background_execution=args.use_background_execution)
    
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
