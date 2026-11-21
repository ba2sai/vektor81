# Outbound-Only Cloudflare Tunnel (cloudflared) for the On-Premise Presidio/SMB/SQL Collector
#
# Architecture Note:
# - Raw PII stays inside the Panamanian on-premise network (Ley 81 Art. 41.4).
# - The collector initiates an outbound-only QUIC/HTTP2 tunnel connection to Cloudflare Edge.
# - No public inbound firewall ports are opened on the enterprise network.

resource "cloudflare_zero_trust_tunnel_cloudflared" "onprem_collector" {
  account_id = var.account_id
  name       = var.tunnel_name
  config_src = "cloudflare"
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "onprem_collector_config" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.onprem_collector.id

  config = {
    warp_routing = {
      enabled = true
    }

    ingress = [
      {
        hostname = var.onprem_collector_hostname
        service  = var.onprem_collector_service_url
        origin_request = {
          connect_timeout        = "30s"
          no_tls_verify          = false
          disable_chunked_encoding = false
        }
      },
      {
        # Required catch-all ingress rule: drops any unmatched inbound route with 404
        service = "http_status:404"
      },
    ]
  }
}
