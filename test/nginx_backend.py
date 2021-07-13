#!/usr/bin/python3

from aiohttp import web

routes = web.RouteTableDef()


@routes.get("/")
async def index(request):
    return web.Response(text="OK")


@routes.get("/sporadic.raucb")
async def sporadic_get(request):
    request.app["sporadic_counter"] += 1
    if request.app["sporadic_counter"] % 2 == 0:
        raise web.HTTPInternalServerError()
    else:
        return web.FileResponse(path="test/good-verity-bundle.raucb")


app = web.Application()
app["sporadic_counter"] = -1
app.add_routes(routes)
web.run_app(app, path="/tmp/backend.sock")
