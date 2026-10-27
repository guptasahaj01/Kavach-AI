"""Single-heavy-request wrapper for a temporary, synthetic public laptop demo."""
import asyncio
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse
from kavach_guard.server import app as gateway


class DemoGate:
    def __init__(self, app):
        self.app = app
        self.lock = asyncio.Lock()

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or scope['method'] in {'GET', 'HEAD', 'OPTIONS'}:
            return await self.app(scope, receive, send)
        if scope['path'] == '/api/v1/benchmark/smoke':
            return await JSONResponse({'detail': 'Run full benchmarks locally; this laptop demo reserves memory for interactive inspections.'}, status_code=503)(scope, receive, send)
        if self.lock.locked():
            return await JSONResponse({'detail': 'The demo is handling another request. Please try again shortly.'}, status_code=429, headers={'Retry-After': '5'})(scope, receive, send)
        async with self.lock:
            await self.app(scope, receive, send)


app = CORSMiddleware(DemoGate(gateway), allow_origins=['https://guptasahaj01.github.io'],
                     allow_methods=['GET', 'POST', 'OPTIONS'], allow_headers=['Content-Type', 'Authorization'])
