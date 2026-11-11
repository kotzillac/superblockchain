# libp2pp2p.py
# P2P networking module using libp2p-python with GossipSub and mDNS

import json
import logging
from collections.abc import Callable

from libp2p import IHost, new_host
from libp2p.discovery.mdns import create_mdns_discovery
from libp2p.pubsub import gossipsub, pubsub
from libp2p.pubsub.pubsub import Pubsub
from libp2p.tools.anyio_service.api import ServiceAPI
from multiaddr import Multiaddr

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Protocol constants
SERVICE_TYPE = "_dochacoin._tcp.local."
TX_TOPIC = "dochacoin/tx"
BLOCK_TOPIC = "dochacoin/block"
GOSSIPSUB_PROTOCOL = "/meshsub/1.2.0"

# Global state
_on_tx_callback: Callable[[dict], bool] | None = None
_on_block_callback: Callable[[dict], bool] | None = None

_host: IHost | None = None
_pubsub: Pubsub | None = None
_mdns_discovery = None
_peers: set[str] = set()


class P2PManager(ServiceAPI):
    """Manages the libp2p host, pubsub, and mDNS discovery."""
    
    def __init__(
        self,
        port: int,
        on_tx_received: Callable[[dict], bool],
        on_block_received: Callable[[dict], bool],
    ):
        global _on_tx_callback, _on_block_callback
        _on_tx_callback = on_tx_received
        _on_block_callback = on_block_received
        
        self.port = port
        self._running = False
    
    async def start(self) -> None:
        """Start the P2P network."""
        global _host, _pubsub, _mdns_discovery
        
        # Create host with mDNS and GossipSub
        listen_addrs = [Multiaddr(f"/ip4/0.0.0.0/tcp/{self.port}")]
        
        _host = new_host(
            enable_mDNS=True,
            listen_addrs=listen_addrs,
            enable_upnp=True,
        )
        
        # Create GossipSub router
        router = gossipsub.GossipSub(
            protocols=[GOSSIPSUB_PROTOCOL],
            degree=6,
            degree_low=4,
            degree_high=12,
        )
        
        # Create Pubsub instance
        _pubsub = pubsub.Pubsub(
            host=_host,
            router=router,
        )
        
        # Start the pubsub service
        await _pubsub.run()
        
        # Subscribe to topics
        await _pubsub.subscribe(TX_TOPIC)
        await _pubsub.subscribe(BLOCK_TOPIC)
        
        # Set up message handlers
        _pubsub.set_topic_validator(TX_TOPIC, self._validate_tx, is_async_validator=True)
        _pubsub.set_topic_validator(BLOCK_TOPIC, self._validate_block, is_async_validator=True)
        
        # Create and start mDNS discovery
        _mdns_discovery = create_mdns_discovery(
            swarm=_host.get_network(),
            port=self.port,
            host=_host,
        )
        await _mdns_discovery.start()
        
        logger.info(f"[*] P2P network started on port {self.port}")
        logger.info(f"[*] Peer ID: {_host.get_id()}")
        logger.info(f"[*] Listening on: {_host.get_addrs()}")
        
        self._running = True
    
    async def stop(self) -> None:
        """Stop the P2P network."""
        global _pubsub, _mdns_discovery
        
        if _pubsub:
            await _pubsub.stop()
            _pubsub = None
        
        if _mdns_discovery:
            await _mdns_discovery.stop()
            _mdns_discovery = None
        
        self._running = False
        logger.info("[*] P2P network stopped")
    
    async def _validate_tx(self, msg: dict) -> bool:
        """Validate transaction message."""
        if _on_tx_callback:
            try:
                tx_data = json.loads(msg.get("data", b"{}"))
                is_new = _on_tx_callback(tx_data)
                return is_new
            except Exception as e:
                logger.warning(f"Failed to validate tx: {e}")
        return False
    
    async def _validate_block(self, msg: dict) -> bool:
        """Validate block message."""
        if _on_block_callback:
            try:
                block_data = json.loads(msg.get("data", b"{}"))
                is_new = _on_block_callback(block_data)
                return is_new
            except Exception as e:
                logger.warning(f"Failed to validate block: {e}")
        return False
    
    async def broadcast_transaction(self, tx_data: dict) -> None:
        """Broadcast a transaction to all peers."""
        if not _pubsub:
            raise RuntimeError("P2P network not started")
        
        data = json.dumps(tx_data).encode()
        await _pubsub.publish(TX_TOPIC, data)
        logger.debug(f"Broadcast transaction: {tx_data.get('id', 'unknown')}")
    
    async def broadcast_block(self, block_data: dict) -> None:
        """Broadcast a block to all peers."""
        if not _pubsub:
            raise RuntimeError("P2P network not started")
        
        data = json.dumps(block_data).encode()
        await _pubsub.publish(BLOCK_TOPIC, data)
        logger.debug(f"Broadcast block: {block_data.get('id', 'unknown')}")


# Global manager instance
_manager: P2PManager | None = None


async def start_network_async(
    port: int,
    on_tx_received: Callable[[dict], bool],
    on_block_received: Callable[[dict], bool],
) -> None:
    """Start the P2P network (async version)."""
    global _manager
    _manager = P2PManager(port, on_tx_received, on_block_received)
    await _manager.start()


def start_network(
    port: int,
    on_tx_received: Callable[[dict], bool],
    on_block_received: Callable[[dict], bool],
) -> None:
    """Start the P2P network (blocking)."""
    import trio
    trio.run(start_network_async, port, on_tx_received, on_block_received)


async def broadcast_transaction_async(tx_data: dict) -> None:
    """Broadcast a transaction (async version)."""
    if not _manager:
        raise RuntimeError("P2P network not started")
    await _manager.broadcast_transaction(tx_data)


async def broadcast_block_async(block_data: dict) -> None:
    """Broadcast a block (async version)."""
    if not _manager:
        raise RuntimeError("P2P network not started")
    await _manager.broadcast_block(block_data)


def broadcast_transaction(tx_data: dict) -> None:
    """Broadcast a transaction (blocking)."""
    import trio
    trio.run(broadcast_transaction_async, tx_data)


def broadcast_block(block_data: dict) -> None:
    """Broadcast a block (blocking)."""
    import trio
    trio.run(broadcast_block_async, block_data)