#!/usr/bin/python3

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


s = open_socket("/tmp/backend.sock")

daemonize()

app = web.Application()
app["rauc"] = {
    "sporadic_counter": -1,
}
app.add_routes(routes)
web.run_app(app, sock=s)
