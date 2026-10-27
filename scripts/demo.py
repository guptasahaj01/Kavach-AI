#!/usr/bin/env python3
"""Start/stop a temporary public KAVACH demo. No paid account or domain required."""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import requests

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / '.demo'
PID = STATE / 'launcher.pid'
API = 'https://api.github.com/repos/guptasahaj01/Kavach-AI'


def publish(url):
    credential = subprocess.run(['git', 'credential', 'fill'], input='protocol=https\nhost=github.com\npath=guptasahaj01/Kavach-AI.git\n\n',
        capture_output=True, text=True, timeout=15, cwd=ROOT, env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'})
    fields = dict(line.split('=', 1) for line in credential.stdout.splitlines() if '=' in line)
    if not fields.get('password'):
        raise RuntimeError('GitHub credentials unavailable. Set repository variable VITE_API_BASE_URL manually to the tunnel URL.')
    session = requests.Session()
    session.headers.update({'Authorization': 'Bearer ' + fields['password'], 'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'})
    endpoint = API + '/actions/variables/VITE_API_BASE_URL'
    result = session.get(endpoint, timeout=20)
    if result.status_code == 404:
        result = session.post(API + '/actions/variables', json={'name': 'VITE_API_BASE_URL', 'value': url}, timeout=20)
    else:
        result.raise_for_status()
        result = session.patch(endpoint, json={'name': 'VITE_API_BASE_URL', 'value': url}, timeout=20)
    result.raise_for_status()
    result = session.post(API + '/actions/workflows/pages.yml/dispatches', json={'ref': 'main'}, timeout=20)
    result.raise_for_status()
    print('GitHub Pages rebuild requested. Allow deployment to finish before refreshing the public site.', flush=True)


def serve(should_publish):
    STATE.mkdir(exist_ok=True)
    PID.write_text(str(os.getpid()))
    children = []
    def interrupt(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupt)
    try:
        env = {**os.environ, 'KAVACH_DB_PATH': str(STATE / 'audit.sqlite'),
               'KAVACH_ALLOWED_ORIGINS': 'https://guptasahaj01.github.io,http://127.0.0.1:5173,http://localhost:5173',
               'HF_HUB_OFFLINE': '1', 'TRANSFORMERS_OFFLINE': '1'}
        backend = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'kavach_guard.demo_server:app', '--host', '127.0.0.1', '--port', '8766'],
            cwd=ROOT, env=env, stdout=(STATE / 'backend.log').open('w'), stderr=subprocess.STDOUT)
        children.append(backend)
        children.append(subprocess.Popen(['caffeinate', '-i', '-w', str(backend.pid)]))
        for _ in range(90):
            if backend.poll() is not None:
                raise RuntimeError('Backend stopped. See .demo/backend.log.')
            try:
                if requests.get('http://127.0.0.1:8766/health', timeout=2).ok:
                    break
            except requests.RequestException:
                pass
            time.sleep(1)
        else:
            raise RuntimeError('Backend startup timed out. See .demo/backend.log.')
        tunnel = subprocess.Popen(['cloudflared', 'tunnel', '--url', 'http://127.0.0.1:8766', '--no-autoupdate'],
            stdout=(STATE / 'tunnel.log').open('w'), stderr=subprocess.STDOUT)
        children.append(tunnel)
        for _ in range(90):
            text = (STATE / 'tunnel.log').read_text()
            match = re.search(r'https://[a-z0-9-]+\.trycloudflare\.com', text)
            if match:
                url = match.group(0)
                break
            if tunnel.poll() is not None:
                raise RuntimeError('Tunnel stopped. See .demo/tunnel.log.')
            time.sleep(1)
        else:
            raise RuntimeError('Tunnel startup timed out. See .demo/tunnel.log.')
        (STATE / 'url.txt').write_text(url + '\n')
        print('Public backend: ' + url, flush=True)
        if should_publish:
            publish(url)
        print('Demo running. Stop using: ./venv/bin/python3 scripts/demo.py stop', flush=True)
        while all(p.poll() is None for p in children):
            time.sleep(2)
    except KeyboardInterrupt:
        pass
    finally:
        for p in reversed(children):
            if p.poll() is None:
                p.terminate()
        for p in children:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        PID.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['start', 'stop', 'status', 'serve'])
    parser.add_argument('--publish', action='store_true', help='Update GitHub backend address and rebuild Pages')
    args = parser.parse_args()
    running = False
    if PID.exists():
        pid = int(PID.read_text())
        process = subprocess.run(['ps', '-p', str(pid), '-o', 'command='], capture_output=True, text=True).stdout
        running = str(Path(__file__).resolve()) in process and 'serve' in process
    if args.command == 'stop':
        if running:
            os.kill(pid, signal.SIGTERM)
        print('Stop requested.' if running else 'Demo is not running.')
    elif args.command == 'status':
        print('Running' if running else 'Stopped')
        if running and (STATE / 'url.txt').exists():
            print((STATE / 'url.txt').read_text().strip())
    elif args.command == 'serve':
        serve(args.publish)
    elif running:
        print('Demo already running.')
    else:
        STATE.mkdir(exist_ok=True)
        command = [sys.executable, str(Path(__file__).resolve()), 'serve'] + (['--publish'] if args.publish else [])
        subprocess.Popen(command, cwd=ROOT, start_new_session=True, stdin=subprocess.DEVNULL,
            stdout=(STATE / 'launcher.log').open('w'), stderr=subprocess.STDOUT)
        print('Starting. Progress: .demo/launcher.log')


if __name__ == '__main__':
    main()
