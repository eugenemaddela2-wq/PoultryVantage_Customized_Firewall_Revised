"""Application-layer source-IP filtering and in-memory request rate limiting."""
import ipaddress
import time
from collections import defaultdict, deque
from flask import request

class GatewayFirewall:
    def __init__(self, allowed_cidrs=None, blocked_ips=None, rate_limit_requests=30,
                 rate_limit_window_seconds=10, ban_duration_seconds=300, trusted_proxy_ips=None):
        self.allowed_cidrs = [ipaddress.ip_network(cidr, strict=False) for cidr in (allowed_cidrs or ["127.0.0.1/32", "::1/128"])]
        self.blocked_ips = set()
        for value in (blocked_ips or []):
            try:
                self.blocked_ips.add(str(ipaddress.ip_address(value)))
            except ValueError:
                continue
        self.trusted_proxy_ips = set(trusted_proxy_ips or [])
        self.rate_limit_requests = max(1, int(rate_limit_requests))
        self.rate_limit_window = max(1, int(rate_limit_window_seconds))
        self.ban_duration = max(1, int(ban_duration_seconds))
        self.request_history = defaultdict(deque)
        self.banned_ips = {}

    def get_client_ip(self):
        """Use forwarded client IP only when request came from explicitly trusted proxy."""
        peer = request.remote_addr or "127.0.0.1"
        if peer in self.trusted_proxy_ips:
            forwarded = request.headers.get("X-Forwarded-For", "").split(",")
            if forwarded and forwarded[0].strip():
                try:
                    return str(ipaddress.ip_address(forwarded[0].strip()))
                except ValueError:
                    pass
        try:
            return str(ipaddress.ip_address(peer))
        except ValueError:
            return "0.0.0.0"

    def is_ip_allowed(self, client_ip):
        try:
            address = ipaddress.ip_address(client_ip)
            return any(address.version == network.version and address in network for network in self.allowed_cidrs)
        except ValueError:
            return False

    def inspect_request(self):
        client_ip = self.get_client_ip()
        now = time.monotonic()
        if client_ip in self.blocked_ips:
            return False, "Firewall: client IP is permanently blocked.", 403
        expiry = self.banned_ips.get(client_ip)
        if expiry and now < expiry:
            return False, f"Firewall: client temporarily banned. Try again in {int(expiry - now)}s.", 429
        self.banned_ips.pop(client_ip, None)
        if not self.is_ip_allowed(client_ip):
            return False, "Firewall: client IP is outside the configured allowed subnets.", 403

        history = self.request_history[client_ip]
        while history and now - history[0] >= self.rate_limit_window:
            history.popleft()
        history.append(now)
        if len(history) > self.rate_limit_requests:
            self.banned_ips[client_ip] = now + self.ban_duration
            return False, f"Firewall: rate limit exceeded; temporarily banned for {self.ban_duration}s.", 429

        # Bound in-memory tracking so one-off source addresses do not grow forever.
        if len(self.request_history) > 5000:
            cutoff = now - self.rate_limit_window
            for ip, events in list(self.request_history.items()):
                while events and now - events[0] >= self.rate_limit_window:
                    events.popleft()
                if not events:
                    self.request_history.pop(ip, None)
            for ip, expiry_time in list(self.banned_ips.items()):
                if expiry_time <= now:
                    self.banned_ips.pop(ip, None)
        return True, None, 200
