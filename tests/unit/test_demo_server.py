import asyncio
from kavach_guard.demo_server import DemoGate


def test_demo_limits_concurrent_heavy_requests_and_releases_slot():
    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()
        async def inner(scope, receive, send):
            entered.set()
            await release.wait()
        gate = DemoGate(inner)
        messages = []
        async def send(message):
            messages.append(message)
        async def receive():
            return {'type': 'http.request', 'body': b''}
        scope = {'type': 'http', 'method': 'POST', 'path': '/api/v1/security/analyze'}
        first = asyncio.create_task(gate(scope, receive, send))
        await entered.wait()
        await gate(scope, receive, send)
        assert messages[0]['status'] == 429
        release.set()
        await first
        assert not gate.lock.locked()
    asyncio.run(scenario())


def test_demo_disables_remote_benchmark():
    async def scenario():
        async def inner(*args):
            raise AssertionError('Benchmark must not run')
        messages = []
        async def send(message):
            messages.append(message)
        await DemoGate(inner)({'type': 'http', 'method': 'POST', 'path': '/api/v1/benchmark/smoke'}, None, send)
        assert messages[0]['status'] == 503
    asyncio.run(scenario())
