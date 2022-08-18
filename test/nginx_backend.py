#!/usr/bin/python3

from aiohttp import web

routes = web.RouteTableDef()


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


app = web.Application()
app["rauc"] = {
    "sporadic_counter": -1,
}
app.add_routes(routes)
web.run_app(app, path="/tmp/backend.sock")
