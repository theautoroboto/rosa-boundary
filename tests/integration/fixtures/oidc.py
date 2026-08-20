"""
OIDC token generation for integration tests.

Supports both real Keycloak authentication and mock JWT generation.
"""

import os
import time
import base64
import json
import hashlib
import hmac
from typing import Dict, List
from datetime import datetime, timedelta

import requests


def get_oidc_token(user: str, password: str = None, mock: bool = False) -> str:
    """
    Get OIDC token for test user.

    Args:
        user: Username (alice, bob, etc.)
        password: User password (required if mock=False)
        mock: If True, generate a mock JWT (for unit-like tests)

    Returns:
        ID token string
    """
    if mock or os.getenv('USE_MOCK_TOKENS') == 'true':
        return generate_mock_jwt(
            sub=user,
            uuid=f'test-uuid-{user}',
            username=user,
            groups=['sre-operators']
        )
    else:
        return keycloak_login(username=user, password=password)


def keycloak_login(username: str, password: str) -> str:
    """
    Perform OIDC PKCE flow with Keycloak and return ID token.

    Requires environment variables:
    - KEYCLOAK_URL: Keycloak base URL
    - KEYCLOAK_REALM: Realm name (default: rosa-boundary)
    - OIDC_CLIENT_ID: Client ID (default: rosa-boundary-sre)

    Args:
        username: Keycloak username
        password: User password

    Returns:
        ID token string

    Raises:
        ValueError: If required env vars are missing
        requests.HTTPError: If authentication fails
    """
    keycloak_url = os.getenv('KEYCLOAK_URL')
    if not keycloak_url:
        raise ValueError("KEYCLOAK_URL environment variable required")

    realm = os.getenv('KEYCLOAK_REALM', 'rosa-boundary')
    client_id = os.getenv('OIDC_CLIENT_ID', 'rosa-boundary-sre')

    token_endpoint = f"{keycloak_url}/realms/{realm}/protocol/openid-connect/token"

    # Direct grant (password flow) - simpler for automated tests
    # In production, CLI uses PKCE browser flow
    data = {
        'grant_type': 'password',
        'client_id': client_id,
        'username': username,
        'password': password,
        'scope': 'openid email profile'
    }

    response = requests.post(token_endpoint, data=data)
    response.raise_for_status()

    token_response = response.json()
    return token_response['id_token']


def generate_mock_jwt(
    sub: str,
    uuid: str,
    username: str,
    groups: List[str],
    exp_hours: int = 1
) -> str:
    """
    Generate a mock JWT for testing without real Keycloak.

    WARNING: This is for testing only. The signature is fake and will not
    validate against any JWKS endpoint. Use only for unit-like integration
    tests that don't call real AWS STS AssumeRoleWithWebIdentity.

    Args:
        sub: Subject (user identifier)
        uuid: User UUID (for ABAC tags)
        username: Preferred username
        groups: List of group memberships
        exp_hours: Token expiration in hours

    Returns:
        JWT string (header.payload.signature)
    """
    now = int(time.time())
    exp = now + (exp_hours * 3600)

    header = {
        'alg': 'RS256',
        'typ': 'JWT',
        'kid': 'mock-key-id'
    }

    payload = {
        'sub': sub,
        'preferred_username': username,
        'uuid': uuid,
        'email': f'{username}@example.com',
        'groups': groups,
        'iss': os.getenv('KEYCLOAK_URL', 'https://keycloak.example.com') + '/realms/rosa-boundary',
        'aud': os.getenv('OIDC_CLIENT_ID', 'rosa-boundary-sre'),
        'iat': now,
        'exp': exp,
        'https://aws.amazon.com/tags': {
            'principal_tags': {
                'uuid': uuid
            }
        }
    }

    # Encode header and payload
    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header).encode()
    ).decode().rstrip('=')

    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).decode().rstrip('=')

    # Fake signature (DO NOT USE IN PRODUCTION)
    # Real JWT validation would fail, but this is enough for tests
    # that only need the token structure
    message = f'{header_b64}.{payload_b64}'
    signature = base64.urlsafe_b64encode(
        hashlib.sha256(message.encode()).digest()
    ).decode().rstrip('=')

    return f'{header_b64}.{payload_b64}.{signature}'


def decode_jwt_payload(token: str) -> Dict:
    """
    Decode JWT payload without verification (for testing/inspection only).

    Args:
        token: JWT string

    Returns:
        Decoded payload dict
    """
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT format: expected 3 parts, got {len(parts)}")

    # Add padding if needed
    payload_b64 = parts[1]
    padding = 4 - (len(payload_b64) % 4)
    if padding != 4:
        payload_b64 += '=' * padding

    payload_bytes = base64.urlsafe_b64decode(payload_b64)
    return json.loads(payload_bytes)
