#!/usr/bin/python3

from aiohttp import web

routes = web.RouteTableDef()


@routes.get("/")
async def index(request):
    return web.Response(text="OK")


app = web.Application()
app.add_routes(routes)
web.run_app(app, path="/tmp/backend.sock")
