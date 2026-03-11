from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Settings:
    bitcoin_rpc_url: str = os.getenv("BITCOIN_RPC_URL", "http://127.0.0.1:8332")
    bitcoin_rpc_user: str = os.getenv("BITCOIN_RPC_USER", "")
    bitcoin_rpc_password: str = os.getenv("BITCOIN_RPC_PASSWORD", "")
    postgres_dsn: str = os.getenv("POSTGRES_DSN", "postgresql://localhost:5432/afci")
    neo4j_uri: str = os.getenv("NEO4J_URI", "bolt://127.0.0.1:7687")
    neo4j_user: str = os.getenv("NEO4J_USER", "neo4j")
    neo4j_password: str = os.getenv("NEO4J_PASSWORD", "")
