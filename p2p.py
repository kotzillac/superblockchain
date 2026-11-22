# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import socket
import logging
from contextlib import asynccontextmanager
from typing import Callable, Optional, Set

import anyio
import httpx
import uvicorn
from fastapi import BackgroundTasks, FastAPI
from zeroconf import IPVersion, ServiceBrowser, ServiceInfo, ServiceListener, Zeroconf

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SERVICE_TYPE = "_dochacoin._tcp.local."

# Global state (protected by locks for thread safety)
PEERS: Set[str] = set()
_peers_lock = asyncio.Lock()

_on_tx_callback: Optional[Callable[[dict], bool]] = None
_on_block_callback: Optional[Callable[[dict], bool]] = None

_zeroconf: Optional[Zeroconf] = None
_browser: Optional[ServiceBrowser] = None
_server: Optional[uvicorn.Server] = None
_shutdown_event = asyncio.Event()


class MDNSListener(ServiceListener):
    """mDNS service listener for peer discovery."""
    
    def __init__(self, my_ip: str, my_port: int):
        self.my_ip = my_ip
        self.my_port = my_port

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        if not info or not info.addresses:
            return
        
        # FIX: info.addresses is a list of bytes, use first IPv4 address
        try:
            peer_ip = socket.inet_ntoa(info.addresses[0])
        except (IndexError, OSError) as e:
            logger.warning(f"Failed to parse peer IP from {info.addresses}: {e}")
            return
            
        peer_url = f"http://{peer_ip}:{info.port}"
        
        # Don't add ourselves
        if info.port != self.my_port or peer_ip != self.my_ip:
            asyncio.run_coroutine_threadsafe(self._add_peer(peer_url), asyncio.get_event_loop())

    async def _add_peer(self, peer_url: str):
        async with _peers_lock:
            PEERS.add(peer_url)
            logger.info(f"[+] Discovered peer: {peer_url}")

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        if info and info.addresses:
            try:
                peer_ip = socket.inet_ntoa(info.addresses[0])
                peer_url = f"http://{peer_ip}:{info.port}"
                asyncio.run_coroutine_threadsafe(self._remove_peer(peer_url), asyncio.get_event_loop())
            except (IndexError, OSError):
                pass

    async def _remove_peer(self, peer_url: str):
        async with _peers_lock:
            PEERS.discard(peer_url)
            logger.info(f"[-] Peer removed: {peer_url}")


app = FastAPI()


@app.post("/tx")
async def handle_tx_http(tx: dict, background_tasks: BackgroundTasks):
    if _on_tx_callback:
        is_new = _on_tx_callback(tx)
        if is_new:
            background_tasks.add_task(_send_to_all, "/tx", tx)
    return {"status": "ok"}


@app.post("/block")
async def handle_block_http(block: dict, background_tasks: BackgroundTasks):
    if _on_block_callback:
        is_new = _on_block_callback(block)
        if is_new:
            background_tasks.add_task(_send_to_all, "/block", block)
    return {"status": "ok"}


@app.get("/peers")
async def get_peers():
    """Return list of known peers."""
    async with _peers_lock:
        return {"peers": list(PEERS)}


async def _send_to_all(endpoint: str, data: dict):
    """Send data to all known peers."""
    async with _peers_lock:
        peers = list(PEERS)
    
    if not peers:
        return
    
    async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
        tasks = []
        for peer in peers:
            tasks.append(_send_to_peer(client, peer, endpoint, data))
        await asyncio.gather(*tasks, return_exceptions=True)


async def _send_to_peer(client: httpx.AsyncClient, peer: str, endpoint: str, data: dict):
    """Send data to a single peer with error logging."""
    try:
        response = await client.post(f"{peer}{endpoint}", json=data)
        response.raise_for_status()
    except httpx.TimeoutException:
        logger.warning(f"Timeout sending {endpoint} to {peer}")
    except httpx.HTTPStatusError as e:
        logger.warning(f"HTTP error sending {endpoint} to {peer}: {e.response.status_code}")
    except httpx.RequestError as e:
        logger.warning(f"Request error sending {endpoint} to {peer}: {type(e).__name__}: {e}")


def _get_lan_ip() -> str:
    """Get the local LAN IP address (not loopback)."""
    # Try to get IP by connecting to a public address
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        pass
    
    # Fallback: enumerate interfaces
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
            for addr in addrs:
                ip = addr.get("addr")
                if ip and not ip.startswith("127."):
                    return ip
    except ImportError:
        pass
    
    # Last resort: hostname (may return 127.0.0.1)
    return socket.gethostbyname(socket.gethostname())


async def _run_zeroconf(port: int, my_ip: str):
    """Run Zeroconf service registration and discovery."""
    global _zeroconf, _browser
    
    _zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
    
    # FIX: Service name should NOT include SERVICE_TYPE twice
    service_name = f"node-{port}.{SERVICE_TYPE}"
    info = ServiceInfo(
        SERVICE_TYPE,
        service_name,
        addresses=[socket.inet_aton(my_ip)],
        port=port,
        properties={},
        server=f"node-{port}.local.",
    )
    
    _zeroconf.register_service(info)
    logger.info(f"[*] Registered mDNS service: {service_name} at {my_ip}:{port}")
    
    _browser = ServiceBrowser(_zeroconf, SERVICE_TYPE, MDNSListener(my_ip, port))
    
    # Wait for shutdown signal
    await _shutdown_event.wait()
    
    # Cleanup
    logger.info("[*] Shutting down mDNS...")
    if _browser:
        _browser.cancel()
    if _zeroconf:
        _zeroconf.unregister_service(info)
        _zeroconf.close()


async def _run_server(port: int):
    """Run the FastAPI server."""
    global _server
    
    config = uvicorn.Config(
        app,
        host="0.0.0.0",
        port=port,
        log_level="warning",
        loop="asyncio",
    )
    _server = uvicorn.Server(config)
    
    # Run server and shutdown event concurrently
    server_task = asyncio.create_task(_server.serve())
    shutdown_task = asyncio.create_task(_shutdown_event.wait())
    
    done, pending = await asyncio.wait(
        [server_task, shutdown_task],
        return_when=asyncio.FIRST_COMPLETED,
    )
    
    # Cancel the other task
    for task in pending:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    
    # Ensure server is stopped
    if _server:
        await _server.shutdown()


async def start_network(
    port: int,
    on_tx_received: Callable[[dict], bool],
    on_block_received: Callable[[dict], bool],
):
    """
    Start the P2P network module.
    
    Args:
        port: Port to listen on
        on_tx_received: Callback(tx) -> bool (return True if tx is new)
        on_block_received: Callback(block) -> bool (return True if block is new)
    
    This function runs until shutdown() is called.
    """
    global _on_tx_callback, _on_block_callback
    
    _on_tx_callback = on_tx_received
    _on_block_callback = on_block_received
    
    my_ip = _get_lan_ip()
    logger.info(f"[*] Starting P2P node on {my_ip}:{port}")
    
    # Run both Zeroconf and HTTP server
    await asyncio.gather(
        _run_zeroconf(port, my_ip),
        _run_server(port),
    )


async def shutdown():
    """Gracefully shutdown the P2P network."""
    logger.info("[*] Initiating shutdown...")
    _shutdown_event.set()
    
    # Wait a bit for cleanup
    await asyncio.sleep(0.5)
    
    async with _peers_lock:
        PEERS.clear()


def broadcast_transaction(tx_data: dict):
    """Broadcast a transaction to all peers (sync, thread-safe)."""
    try:
        # Try to get running loop
        loop = asyncio.get_running_loop()
        loop.create_task(_send_to_all("/tx", tx_data))
    except RuntimeError:
        # No running loop, create one
        asyncio.run(_send_to_all("/tx", tx_data))


def broadcast_block(block_data: dict):
    """Broadcast a block to all peers (sync, thread-safe)."""
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_send_to_all("/block", block_data))
    except RuntimeError:
        asyncio.run(_send_to_all("/block", block_data))


# For backward compatibility
def get_peers_list() -> list:
    """Get current peers list (sync)."""
    try:
        loop = asyncio.get_running_loop()
        # Can't easily get set from sync context, return empty
        return []
    except RuntimeError:
        return []