#!/usr/bin/python3

import argparse
import json
import os
import socket
import sys

try:
    from aiohttp import web
except ModuleNotFoundError:
    print("aiohttp python module not installed, disabling RAUC_TEST_HTTP_BACKEND")
    exit(1)

routes = web.RouteTableDef()


def daemonize():
    if os.fork():
        sys.exit()

    os.setsid()

    if os.fork():
        sys.exit()


def open_socket(name):
    try:
        os.unlink(name)
    except FileNotFoundError:
        pass
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(name)
    os.chmod(name, 0o666)
    return s


@routes.get("/")
async def index(request):
    return web.Response(text="OK")


@routes.get("/sporadic.raucb")
async def sporadic_get(request):
    request.app["rauc"]["sporadic_counter"] += 1
    if request.app["rauc"]["sporadic_counter"] % 2 == 0:
        raise web.HTTPInternalServerError()
    else:
        return web.FileResponse(path="test/good-verity-bundle.raucb")


@routes.get("/token.raucb")
async def token_get(request):
    if "token" not in request.cookies:
        raise web.HTTPUnauthorized(text="missing cookie token")
    elif request.cookies["token"] != "secret":
        raise web.HTTPUnauthorized(text="bad cookie token")
    else:
        return web.FileResponse(path="test/good-verity-bundle.raucb")


def reset_summary(request):
    request.app["rauc"]["summary"] = {
        "first_request_headers": {},
        "second_request_headers": {},
        "requests": 0,
        "range_requests": [],
    }


@routes.post("/setup")
async def setup_handler(request):
    try:
        data = await request.json()
        if "file_path" not in data and "http_code" not in data:
            return web.Response(text="missing file_path or http_code", status=400)

        request.app["rauc"]["config"] = data
        reset_summary(request)

        return web.Response(text="OK")
    except json.JSONDecodeError:
        return web.Response(text="bad JSON", status=400)


@routes.get("/get")
async def get_handler(request):
    config = request.app["rauc"].get("config", {})
    if not config:
        return web.Response(text="not set up yet", status=400)

    summary = request.app["rauc"]["summary"]
    summary["requests"] += 1

    if not summary["first_request_headers"]:
        summary["first_request_headers"] = dict(request.headers)
    elif not summary["second_request_headers"]:
        summary["second_request_headers"] = dict(request.headers)

    http_code = config.get("http_code")
    if http_code:
        return web.Response(status=http_code)

    if request.http_range:
        start = str(request.http_range.start) or ""
        end = str(request.http_range.stop) or ""
        summary["range_requests"].append(f"{start}:{end}")

    return web.FileResponse(config["file_path"])


@routes.get("/summary")
async def summary_handler(request):
    summary = request.app["rauc"].get("summary", {})
    reset_summary(request)
    return web.json_response(summary)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run aiohttp server with optional socket and daemon mode.")
    parser.add_argument("-s", "--socket", help="Path to Unix domain socket")
    parser.add_argument("-d", "--daemon", action="store_true", help="Run as daemon")

    args = parser.parse_args()

    app_args = {}

    if args.socket:
        app_args["sock"] = open_socket(args.socket)
    else:
        app_args["host"] = "127.0.0.1"
        app_args["port"] = 8080

    if args.daemon:
        daemonize()

    app = web.Application()
    app["rauc"] = {
        "sporadic_counter": -1,
    }
    app.add_routes(routes)
    web.run_app(app, **app_args)
