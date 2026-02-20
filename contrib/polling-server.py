#!/usr/bin/env python3

import argparse
from datetime import datetime

from aiohttp import web


class PollingServer:
    HEADERS = {
        "boot-id": "RAUC-Boot-ID",
        "machine-id": "RAUC-Machine-ID",
        "serial": "RAUC-Serial",
        "system-version": "RAUC-System-Version",
        "transaction-id": "RAUC-Transaction-ID",
        "uptime": "RAUC-Uptime",
        "variant": "RAUC-Variant",
    }

    LOG_LINE = "{timestamp} | Redirecting {machine-id},{serial} to {Location}"

    def __init__(self, upstream_url, columns):
        self.upstream_url = upstream_url
        self.columns = columns.split(",")

        self.polls = list()

        self.app = web.Application()
        self.app.router.add_route("GET", "/", self.get_index)
        self.app.router.add_route("GET", "/update.raucb", self.get_bundle)

    async def get_index(self, request):
        """Output a HTML table of previous bundle polling attempts"""

        def enc(text):
            return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        html = [
            "<html>",
            "<body>",
            '<table style="width: 100%;max-width: 60em;text-align: left;margin: 5em auto;">',
        ]

        html.append("<tr>")
        html.extend(
            f'<th style="border-bottom: solid 1px black;">{enc(col)}</th>'
            for col in self.columns
        )
        html.append("</tr>")

        for poll_info in self.polls:
            html.append("<tr>")
            html.extend(f"<th>{enc(poll_info[col])}</th>" for col in self.columns)
            html.append("</tr>")

        html.extend(("</table>", "</body>", "</html>"))

        return web.Response(text="\n".join(html), content_type="text/html")

    async def get_bundle(self, request):
        """Respond to bundle polling attempts

        Stores the provided headers for use by `get_index` and redirects to
        the actual location of the bundle.
        """

        poll_info = dict(
            (name, request.headers.get(header_name, "-"))
            for (name, header_name) in self.HEADERS.items()
        )

        poll_info["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        self.polls.append(poll_info)

        response_headers = {"Location": self.upstream_url.format(**poll_info)}

        print(self.LOG_LINE.format(**poll_info, **response_headers))

        return web.Response(status=307, headers=response_headers)

    def run(self, port=8080):
        web.run_app(self.app, port=port)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "An example server that shows how to interpret RAUC HTTP headers "
            "and use HTTP redirects to serve clients-specific bundles. "
            "It provides an overview table on `/` and a bundle url for use with "
            "RAUC on `/update.raucb`."
        )
    )

    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=8080,
        help=("The port the server will listen on. [default: %(default)s]"),
    )

    parser.add_argument(
        "-u",
        "--upstream-url",
        default="http://example.invalid/bundles/{machine-id}.raucb",
        help=(
            "The upstream bundle URL. Python `format()` is used to replace "
            "placeholders with values received in the request headers. "
            "[default: %(default)s]"
        ),
    )

    parser.add_argument(
        "-c",
        "--columns",
        default="timestamp,machine-id,boot-id,uptime",
        help=("Table columns to show in the overview table. [default: %(default)s]"),
    )

    args = parser.parse_args()

    server = PollingServer(upstream_url=args.upstream_url, columns=args.columns)
    server.run(args.port)


if __name__ == "__main__":
    main()
