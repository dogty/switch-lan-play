#include "ipv4.h"

int send_ipv4(
    struct packet_ctx *arg,
    const void *dst,
    uint8_t protocol,
    const struct payload *payload
)
{
    return send_ipv4_ex(
        arg,
        arg->ip,
        dst,
        protocol,
        payload
    );
}
int send_ipv4_ex(
    struct packet_ctx *arg,
    const void *src,
    const void *dst,
    uint8_t protocol,
    const struct payload *payload
)
{
    struct payload part;
    uint8_t dst_mac[6];
    uint8_t buffer[IPV4_HEADER_LEN];
    uint8_t *buf = buffer;

    WRITE_NET8(buf, IPV4_OFF_VER_LEN, 0x45);
    WRITE_NET8(buf, IPV4_OFF_DSCP_ECN, 0x00);
    WRITE_NET16(buf, IPV4_OFF_TOTAL_LEN, IPV4_HEADER_LEN + payload_total_len(payload));
    WRITE_NET16(buf, IPV4_OFF_ID, arg->identification++);
    WRITE_NET16(buf, IPV4_OFF_FLAGS_FRAG_OFFSET, 0);
    WRITE_NET8(buf, IPV4_OFF_TTL, 128);
    WRITE_NET8(buf, IPV4_OFF_PROTOCOL, protocol);
    WRITE_NET16(buf, IPV4_OFF_CHECKSUM, 0x0000);

    CPY_IPV4(buf + IPV4_OFF_SRC, src);
    CPY_IPV4(buf + IPV4_OFF_DST, dst);

    uint16_t checksum = calc_checksum(buffer, IPV4_HEADER_LEN);
    WRITE_NET16(buf, IPV4_OFF_CHECKSUM, checksum);

    part.ptr = buffer;
    part.len = IPV4_HEADER_LEN;
    part.next = payload;

    if (!arp_get_mac_by_ip(arg, dst_mac, dst)) {
        return false;
    }

    return send_ether(
        arg,
        dst_mac,
        ETHER_TYPE_IPV4,
        &part
    );
}

void parse_ipv4(const struct ether_frame *ether, struct ipv4 *ipv4)
{
    const u_char *packet = ether->payload;
    uint8_t t;
    uint16_t tt;

    ipv4->ether = ether;
    t = READ_NET8(packet, IPV4_OFF_VER_LEN);
    ipv4->version = t >> 4;
    ipv4->header_len = (t & 0xF) * 4;
    t = READ_NET8(packet, IPV4_OFF_DSCP_ECN);
    ipv4->dscp = t >> 2;
    ipv4->ecn = t & 3; // 0b11
    ipv4->total_len = READ_NET16(packet, IPV4_OFF_TOTAL_LEN);
    ipv4->identification = READ_NET16(packet, IPV4_OFF_ID);
    tt = READ_NET16(packet, IPV4_OFF_FLAGS_FRAG_OFFSET);
    ipv4->flags = tt >> 13;
    ipv4->fragment_offset = tt & 0x1fff;
    ipv4->ttl = READ_NET8(packet, IPV4_OFF_TTL);
    ipv4->protocol = READ_NET8(packet, IPV4_OFF_PROTOCOL);
    ipv4->checksum = READ_NET16(packet, IPV4_OFF_PROTOCOL);
    CPY_IPV4(ipv4->src, packet + IPV4_OFF_SRC);
    CPY_IPV4(ipv4->dst, packet + IPV4_OFF_DST);
    ipv4->payload = packet + ipv4->header_len;
}

struct broadcast_relay_ctx {
    struct packet_ctx *packet_ctx;
    const uint8_t *src_ip;
    const uint8_t *packet;
    uint16_t len;
};

/* Opt-in local broadcast relay: LANPLAY_RELAY_ONLY_FROM=ip[,ip...] re-sends
   broadcasts from the listed consoles to every other local console as
   unicast ethernet frames. Useful when a WiFi AP won't deliver one console's
   broadcast stream to another; kept opt-in and per-source because relaying a
   direction that already works would deliver every packet twice
   (direct + relayed copy). Unset = no local relay at all. */
static bool relay_src_allowed(const uint8_t *src_ip)
{
    static int allow_count = -2;            /* -2 = not parsed yet */
    static uint8_t allow[8][4];

    if (allow_count == -2) {
        const char *env = getenv("LANPLAY_RELAY_ONLY_FROM");
        allow_count = 0;
        if (env && *env) {
            const char *p = env;
            while (*p && allow_count < 8) {
                unsigned a, b, c, d;
                int n = 0;
                if (sscanf(p, "%u.%u.%u.%u%n", &a, &b, &c, &d, &n) == 4
                        && a < 256 && b < 256 && c < 256 && d < 256) {
                    allow[allow_count][0] = a;
                    allow[allow_count][1] = b;
                    allow[allow_count][2] = c;
                    allow[allow_count][3] = d;
                    allow_count++;
                    p += n;
                }
                while (*p && *p != ',') p++;
                if (*p == ',') p++;
            }
            LLOG(LLOG_INFO, "local broadcast relay enabled for %d source ip(s)", allow_count);
        }
    }
    for (int i = 0; i < allow_count; i++) {
        if (CMP_IPV4(allow[i], src_ip)) {
            return true;
        }
    }
    return false;
}
static int relay_broadcast_cb(void *p, const struct arp_item *item)
{
    struct broadcast_relay_ctx *ctx = p;
    struct payload part;

    if (CMP_IPV4(item->ip, ctx->src_ip)) {
        return 0; /* never echo a broadcast back to its sender */
    }
    part.ptr = ctx->packet;
    part.len = ctx->len;
    part.next = NULL;
    send_ether(ctx->packet_ctx, item->mac, ETHER_TYPE_IPV4, &part);
    return 0;
}

int process_ipv4(struct packet_ctx *arg, const struct ether_frame *ether)
{
    struct ipv4 ipv4;
    parse_ipv4(ether, &ipv4);
    arp_set(arg, ipv4.ether->src, ipv4.src);

    if (CMP_IPV4(ipv4.dst, arg->ip)) {
        switch (ipv4.protocol) {
            case IPV4_PROTOCOL_ICMP:
                return process_icmp(arg, &ipv4);
        }
    } else if (IS_SUBNET(ipv4.dst, arg->subnet_net, arg->subnet_mask)) {
        if (IS_BROADCAST(ipv4.dst, arg->subnet_net, arg->subnet_mask)) {
            /* Forward the broadcast to the relay server, and relay it locally
               to every other console we know (as unicast ethernet frames,
               which WiFi delivers reliably — real broadcast frames between
               wireless clients are unacknowledged and often dropped or not
               re-forwarded at all by the AP; captures show one console never
               receiving the other's game broadcasts, e.g. Street Fighter
               30th AC on UDP :12345, which then fails with 2618-0006).
               This used to re-send the packet to the sender's OWN mac
               instead, so every console heard an echo of everything it
               broadcast — something that never happens on a real LAN, and
               which broke broadcast-based games and made ldn_mitm scans find
               their own network. The sender is explicitly skipped now. */
            lan_client_send_ipv4(arg->arg, ipv4.dst, ipv4.ether->payload, ipv4.total_len);

            struct broadcast_relay_ctx ctx;
            ctx.packet_ctx = arg;
            ctx.src_ip = ipv4.src;
            ctx.packet = ipv4.ether->payload;
            ctx.len = ipv4.total_len;
            if (relay_src_allowed(ipv4.src)) {
                arp_for_each(arg, &ctx, relay_broadcast_cb);
            }
            return 0;
        } else if (arp_has_ip(arg, ipv4.dst)) {
            uint8_t dst_mac[6];
            struct payload part;
            arp_get_mac_by_ip(arg, dst_mac, ipv4.dst);
            part.ptr = ipv4.ether->payload;
            part.len = ipv4.total_len;
            part.next = NULL;
            return send_ether(arg, dst_mac, ETHER_TYPE_IPV4, &part);
        } else {
            return lan_client_send_ipv4(arg->arg, ipv4.dst, ipv4.ether->payload, ipv4.total_len);
        }
    } else if (CMP_MAC(arg->mac, ether->dst)) {
        // target ip is not us but target mac is us
        // we are now a gateway

        gateway_on_packet(arg->arg->gateway, ether->raw, ether->raw_len);

        return 0;
    }

    return 0;
}

uint16_t calc_checksum(const u_char *buffer, int len)
{
    uint32_t sum = 0;
    uint16_t *buf = (uint16_t *)buffer;
    while (len > 1) {
        sum += ntohs(*buf++);
        len -= sizeof(uint16_t);
    }
    if (len) {
        sum += *(uint8_t *)buf;
    }
    while (sum > 0xffff) {
        sum -= 0xffff;
    }
    return ~sum;
}

uint16_t calc_payload_checksum(const struct payload *payload)
{
    uint32_t sum = 0;
    int offset = 0;
    const struct payload *part = payload;

    while (part) {
        uint16_t *buf = (uint16_t *)part->ptr + offset;
        int len = part->len - offset;
        while (len > 1) {
            sum += ntohs(*buf++);
            len -= sizeof(uint16_t);
        }

        part = part->next;
        if (len) {
            if (part) {
                sum += (READ_NET8(buf, 0) << 8) | (READ_NET8(part->ptr, 0));
            } else {
                sum += READ_NET8(buf, 0) << 8;
            }
            offset = 1;
        } else {
            offset = 0;
        }
    }

    while (sum > 0xffff) {
        sum -= 0xffff;
    }

    return ~sum;
}
