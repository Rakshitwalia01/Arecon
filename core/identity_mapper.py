#!/usr/bin/env python3
"""
ARECON Authentication & Identity Flow Mapper (core/identity_mapper.py)
Author: Rakshit Walia
Copyright: (c) 2026 Rakshit Walia. All rights reserved.
License: MIT License

Discovers:
- SSO, OAuth 2.0 / OIDC configuration endpoints
- SAML 2.0 Service Provider metadata
- Account lifecycle routes (login, register, reset password)
- Identity Provider dependencies (Okta, Auth0, Keycloak, Firebase)
"""

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Set, Tuple

USER_AGENT = "Mozilla/5.0 (compatible; ARECON-IdentityMapper/2.0; +https://authorized-bugbounty.org)"

OIDC_WELL_KNOWN = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth2/.well-known/openid-configuration",
]

SAML_PATHS = [
    "/saml/metadata",
    "/saml2/metadata",
    "/auth/saml/metadata",
    "/simplesaml/module.php/saml/sp/metadata.php",
]

AUTH_FLOW_PATHS = [
    "/login",
    "/signin",
    "/auth/login",
    "/signup",
    "/register",
    "/auth/register",
    "/forgot-password",
    "/reset-password",
    "/sso/login",
    "/oauth/authorize",
]


class IdentityMapper:
    def __init__(self, timeout: float = 3.5):
        self.timeout = timeout
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def _safe_get(self, url: str) -> Tuple[int, Dict[str, str], bytes]:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read(50000)
        except urllib.error.HTTPError as e:
            return e.code, {k.lower(): v for k, v in e.headers.items()}, b""
        except Exception:
            return 0, {}, b""

    def map_identity(self, base_url: str) -> Dict[str, Any]:
        """Maps authentication and identity configurations for a target web application."""
        parsed = urllib.parse.urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        oidc_config = None
        saml_metadata = None
        auth_routes = []

        # 1. Check OpenID Connect / OAuth Configuration
        for path in OIDC_WELL_KNOWN:
            check_url = urllib.parse.urljoin(origin, path)
            status, _, body = self._safe_get(check_url)
            if status == 200 and body:
                try:
                    data = json.loads(body.decode("utf-8", errors="ignore"))
                    if "authorization_endpoint" in data or "issuer" in data:
                        oidc_config = {
                            "config_url": check_url,
                            "issuer": data.get("issuer"),
                            "authorization_endpoint": data.get("authorization_endpoint"),
                            "token_endpoint": data.get("token_endpoint"),
                            "userinfo_endpoint": data.get("userinfo_endpoint"),
                            "jwks_uri": data.get("jwks_uri"),
                            "scopes_supported": data.get("scopes_supported", []),
                            "response_types_supported": data.get("response_types_supported", []),
                        }
                        break
                except Exception:
                    pass

        # 2. Check SAML Metadata
        for path in SAML_PATHS:
            check_url = urllib.parse.urljoin(origin, path)
            status, headers, body = self._safe_get(check_url)
            if status == 200 and (b"EntityDescriptor" in body or b"SPSSODescriptor" in body):
                saml_metadata = {
                    "metadata_url": check_url,
                    "content_type": headers.get("content-type", "xml"),
                }
                break

        # 3. Check Auth Workflow endpoints
        for path in AUTH_FLOW_PATHS:
            check_url = urllib.parse.urljoin(origin, path)
            status, _, body = self._safe_get(check_url)
            if status in (200, 301, 302, 401, 403):
                auth_routes.append({
                    "url": check_url,
                    "path": path,
                    "status": status,
                })

        return {
            "origin": origin,
            "oidc_configuration": oidc_config,
            "saml_metadata": saml_metadata,
            "discovered_auth_routes": auth_routes,
        }
