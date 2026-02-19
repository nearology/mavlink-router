/*
 * This file is part of the MAVLink Router project
 *
 * Copyright (C) 2016  Intel Corporation. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "endpoint.h"

#include <algorithm>
#include <climits>
#include <regex>
#include <utility>

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/serial.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <common/log.h>
#include <common/util.h>
#include <common/xtermios.h>

#include "mainloop.h"

#define RX_BUF_MAX_SIZE (MAVLINK_MAX_PACKET_LEN * 4)
#define TX_BUF_MAX_SIZE (8U * 1024U)

#define UART_BAUD_RETRY_SEC 5

namespace {
constexpr uint8_t SBUS_START_BYTE = 0x0f;
constexpr uint8_t SBUS_END_BYTE = 0x00;
constexpr uint8_t SBUS_END_BYTE_ALT_1 = 0x04;
constexpr uint8_t SBUS_END_BYTE_ALT_2 = 0x14;
constexpr uint8_t SBUS_END_BYTE_ALT_3 = 0x24;
constexpr uint16_t SBUS_MIN = 1000U;
constexpr uint16_t SBUS_MAX = 2000U;
constexpr uint8_t SBUS_TARGET_SYSTEM_ID = 0;
constexpr uint8_t SBUS_TARGET_COMPONENT_ID = MAV_COMP_ID_AUTOPILOT1;
} // namespace

uint16_t Endpoint::sniffer_sysid = 0;

// clang-format off
const char *UartEndpoint::section_pattern = "uartendpoint *";
const ConfFile::OptionsTable UartEndpoint::option_table[] = {
    {"baud",            false, ConfFile::parse_uint32_vector,   OPTIONS_TABLE_STRUCT_FIELD(UartEndpointConfig, baudrates)},
    {"device",          true,  ConfFile::parse_stdstring,       OPTIONS_TABLE_STRUCT_FIELD(UartEndpointConfig, device)},
    {"FlowControl",     false, ConfFile::parse_bool,            OPTIONS_TABLE_STRUCT_FIELD(UartEndpointConfig, flowcontrol)},
    {"AllowMsgIdOut",   false, ConfFile::parse_uint32_vector,   OPTIONS_TABLE_STRUCT_FIELD(UartEndpointConfig, allow_msg_id_out)},
    {"BlockMsgIdOut",   false, ConfFile::parse_uint32_vector,   OPTIONS_TABLE_STRUCT_FIELD(UartEndpointConfig, block_msg_id_out)},
    {"AllowSrcCompOut", false, ConfFile::parse_uint8_vector,    OPTIONS_TABLE_STRUCT_FIELD(UartEndpointConfig, allow_src_comp_out)},
    {"BlockSrcCompOut", false, ConfFile::parse_uint8_vector,    OPTIONS_TABLE_STRUCT_FIELD(UartEndpointConfig, block_src_comp_out)},
    {"AllowSrcSysOut",  false, ConfFile::parse_uint8_vector,    OPTIONS_TABLE_STRUCT_FIELD(UartEndpointConfig, allow_src_sys_out)},
    {"BlockSrcSysOut",  false, ConfFile::parse_uint8_vector,    OPTIONS_TABLE_STRUCT_FIELD(UartEndpointConfig, block_src_sys_out)},
    {"AllowMsgIdIn",    false, ConfFile::parse_uint32_vector,   OPTIONS_TABLE_STRUCT_FIELD(UartEndpointConfig, allow_msg_id_in)},
    {"BlockMsgIdIn",    false, ConfFile::parse_uint32_vector,   OPTIONS_TABLE_STRUCT_FIELD(UartEndpointConfig, block_msg_id_in)},
    {"AllowSrcCompIn",  false, ConfFile::parse_uint8_vector,    OPTIONS_TABLE_STRUCT_FIELD(UartEndpointConfig, allow_src_comp_in)},
    {"BlockSrcCompIn",  false, ConfFile::parse_uint8_vector,    OPTIONS_TABLE_STRUCT_FIELD(UartEndpointConfig, block_src_comp_in)},
    {"AllowSrcSysIn",   false, ConfFile::parse_uint8_vector,    OPTIONS_TABLE_STRUCT_FIELD(UartEndpointConfig, allow_src_sys_in)},
    {"BlockSrcSysIn",   false, ConfFile::parse_uint8_vector,    OPTIONS_TABLE_STRUCT_FIELD(UartEndpointConfig, block_src_sys_in)},
    {"group",           false, ConfFile::parse_stdstring,       OPTIONS_TABLE_STRUCT_FIELD(UartEndpointConfig, group)},
    {}
};

const char *UdpEndpoint::section_pattern = "udpendpoint *";
const ConfFile::OptionsTable UdpEndpoint::option_table[] = {
    {"address",         true,   ConfFile::parse_stdstring,      OPTIONS_TABLE_STRUCT_FIELD(UdpEndpointConfig, address)},
    {"mode",            true,   UdpEndpoint::parse_udp_mode,    OPTIONS_TABLE_STRUCT_FIELD(UdpEndpointConfig, mode)},
    {"port",            false,  ConfFile::parse_ul,             OPTIONS_TABLE_STRUCT_FIELD(UdpEndpointConfig, port)},
    {"filter",          false,  ConfFile::parse_uint32_vector,  OPTIONS_TABLE_STRUCT_FIELD(UdpEndpointConfig, allow_msg_id_out)}, // legacy AllowMsgIdOut
    {"AllowMsgIdOut",   false,  ConfFile::parse_uint32_vector,  OPTIONS_TABLE_STRUCT_FIELD(UdpEndpointConfig, allow_msg_id_out)},
    {"BlockMsgIdOut",   false,  ConfFile::parse_uint32_vector,  OPTIONS_TABLE_STRUCT_FIELD(UdpEndpointConfig, block_msg_id_out)},
    {"AllowSrcCompOut", false,  ConfFile::parse_uint8_vector,   OPTIONS_TABLE_STRUCT_FIELD(UdpEndpointConfig, allow_src_comp_out)},
    {"BlockSrcCompOut", false,  ConfFile::parse_uint8_vector,   OPTIONS_TABLE_STRUCT_FIELD(UdpEndpointConfig, block_src_comp_out)},
    {"AllowSrcSysOut",  false,  ConfFile::parse_uint8_vector,   OPTIONS_TABLE_STRUCT_FIELD(UdpEndpointConfig, allow_src_sys_out)},
    {"BlockSrcSysOut",  false,  ConfFile::parse_uint8_vector,   OPTIONS_TABLE_STRUCT_FIELD(UdpEndpointConfig, block_src_sys_out)},
    {"AllowMsgIdIn",    false,  ConfFile::parse_uint32_vector,  OPTIONS_TABLE_STRUCT_FIELD(UdpEndpointConfig, allow_msg_id_in)},
    {"BlockMsgIdIn",    false,  ConfFile::parse_uint32_vector,  OPTIONS_TABLE_STRUCT_FIELD(UdpEndpointConfig, block_msg_id_in)},
    {"AllowSrcCompIn",  false,  ConfFile::parse_uint8_vector,   OPTIONS_TABLE_STRUCT_FIELD(UdpEndpointConfig, allow_src_comp_in)},
    {"BlockSrcCompIn",  false,  ConfFile::parse_uint8_vector,   OPTIONS_TABLE_STRUCT_FIELD(UdpEndpointConfig, block_src_comp_in)},
    {"AllowSrcSysIn",   false,  ConfFile::parse_uint8_vector,   OPTIONS_TABLE_STRUCT_FIELD(UdpEndpointConfig, allow_src_sys_in)},
    {"BlockSrcSysIn",   false,  ConfFile::parse_uint8_vector,   OPTIONS_TABLE_STRUCT_FIELD(UdpEndpointConfig, block_src_sys_in)},
    {"group",           false,  ConfFile::parse_stdstring,      OPTIONS_TABLE_STRUCT_FIELD(UdpEndpointConfig, group)},
    {}
};

const char *TcpEndpoint::section_pattern = "tcpendpoint *";
const ConfFile::OptionsTable TcpEndpoint::option_table[] = {
    {"address",         true,   ConfFile::parse_stdstring,      OPTIONS_TABLE_STRUCT_FIELD(TcpEndpointConfig, address)},
    {"port",            true,   ConfFile::parse_ul,             OPTIONS_TABLE_STRUCT_FIELD(TcpEndpointConfig, port)},
    {"RetryTimeout",    false,  ConfFile::parse_i,              OPTIONS_TABLE_STRUCT_FIELD(TcpEndpointConfig, retry_timeout)},
    {"AllowMsgIdOut",   false,  ConfFile::parse_uint32_vector,  OPTIONS_TABLE_STRUCT_FIELD(TcpEndpointConfig, allow_msg_id_out)},
    {"BlockMsgIdOut",   false,  ConfFile::parse_uint32_vector,  OPTIONS_TABLE_STRUCT_FIELD(TcpEndpointConfig, block_msg_id_out)},
    {"AllowSrcCompOut", false,  ConfFile::parse_uint8_vector,   OPTIONS_TABLE_STRUCT_FIELD(TcpEndpointConfig, allow_src_comp_out)},
    {"BlockSrcCompOut", false,  ConfFile::parse_uint8_vector,   OPTIONS_TABLE_STRUCT_FIELD(TcpEndpointConfig, block_src_comp_out)},
    {"AllowSrcSysOut",  false,  ConfFile::parse_uint8_vector,   OPTIONS_TABLE_STRUCT_FIELD(TcpEndpointConfig, allow_src_sys_out)},
    {"BlockSrcSysOut",  false,  ConfFile::parse_uint8_vector,   OPTIONS_TABLE_STRUCT_FIELD(TcpEndpointConfig, block_src_sys_out)},
    {"AllowMsgIdIn",    false,  ConfFile::parse_uint32_vector,  OPTIONS_TABLE_STRUCT_FIELD(TcpEndpointConfig, allow_msg_id_in)},
    {"BlockMsgIdIn",    false,  ConfFile::parse_uint32_vector,  OPTIONS_TABLE_STRUCT_FIELD(TcpEndpointConfig, block_msg_id_in)},
    {"AllowSrcCompIn",  false,  ConfFile::parse_uint8_vector,   OPTIONS_TABLE_STRUCT_FIELD(TcpEndpointConfig, allow_src_comp_in)},
    {"BlockSrcCompIn",  false,  ConfFile::parse_uint8_vector,   OPTIONS_TABLE_STRUCT_FIELD(TcpEndpointConfig, block_src_comp_in)},
    {"AllowSrcSysIn",   false,  ConfFile::parse_uint8_vector,   OPTIONS_TABLE_STRUCT_FIELD(TcpEndpointConfig, allow_src_sys_in)},
    {"BlockSrcSysIn",   false,  ConfFile::parse_uint8_vector,   OPTIONS_TABLE_STRUCT_FIELD(TcpEndpointConfig, block_src_sys_in)},
    {"group",           false,  ConfFile::parse_stdstring,      OPTIONS_TABLE_STRUCT_FIELD(TcpEndpointConfig, group)},
    {}
};
// clang-format on

static bool ip_str_is_ipv6(const char *ip)
{
    /* Square brackets always exist on IPv6 addresses b/c of input validation */
    return strchr(ip, '[') != nullptr;
}

static bool ipv6_is_linklocal(const char *ip)
{
    /* link-local addresses start with fe80, ULA addresses are in fc::/7 range */
    return (strncmp(ip, "fe80", 4) == 0 || strncmp(ip, "fc", 2) == 0 || strncmp(ip, "fd", 2) == 0);
}

static bool ipv6_is_multicast(const char *ip)
{
    /* multicast addresses start with ff0x (most of the time) */
    return strncmp(ip, "ff0", 3) == 0;
}

static bool validate_ipv6(const std::string &ip)
{
    // simplyfied pattern
    std::regex ipv6_regex("\\[(([a-f\\d]{0,4}:)+[a-f\\d]{0,4})\\]");
    return std::regex_match(ip, ipv6_regex);
}

static bool validate_ipv4(const std::string &ip)
{
    std::regex ipv4_regex("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})");
    return regex_match(ip, ipv4_regex);
}

static bool validate_ip(const std::string &ip)
{
    return validate_ipv4(ip) || validate_ipv6(ip);
}

static unsigned int ipv6_get_scope_id(const char *ip)
{
    struct ifaddrs *addrs;
    char ipAddress[NI_MAXHOST];
    unsigned scope = 0;
    getifaddrs(&addrs);

    /* search for our address in all interface addresses */
    for (ifaddrs *addr = addrs; addr; addr = addr->ifa_next) {
        if (addr->ifa_addr && addr->ifa_addr->sa_family == AF_INET6) {
            getnameinfo(addr->ifa_addr,
                        sizeof(struct sockaddr_in6),
                        ipAddress,
                        sizeof(ipAddress),
                        nullptr,
                        0,
                        NI_NUMERICHOST);

            /* cut the interface name from the end of a link-local address */
            auto *search = strrchr(ipAddress, '%');
            if (search != nullptr) {
                *search = '\0';
            }

            /* convert to a scope ID, if it's our interface */
            if (strcmp(ipAddress, ip) == 0) {
                scope = if_nametoindex(addr->ifa_name);
                break;
            }
        }
    }

    freeifaddrs(addrs);
    return scope;
}

Endpoint::Endpoint(std::string type, std::string name)
    : _type{std::move(type)}
    , _name{std::move(name)}
{
    rx_buf.data = (uint8_t *)malloc(RX_BUF_MAX_SIZE);
    rx_buf.len = 0;
    tx_buf.data = (uint8_t *)malloc(TX_BUF_MAX_SIZE);
    tx_buf.len = 0;

    assert(rx_buf.data);
    assert(tx_buf.data);
}

Endpoint::~Endpoint()
{
    free(rx_buf.data);
    free(tx_buf.data);
}

bool Endpoint::handle_canwrite()
{
    int r = flush_pending_msgs();
    return r == -EAGAIN;
}

int Endpoint::handle_read()
{
    struct buffer buf = {};
    int r;

    for (;;) {
        r = read_msg(&buf);
        if (r <= 0) {
            break;
        }

        // check incoming message filters
        if (!allowed_by_dedup(&buf)) {
            if (Log::get_max_level() >= Log::Level::DEBUG) {
                log_trace("Message %u discarded by de-duplication", buf.curr.msg_id);
            }
        } else if (!allowed_by_incoming_filters(&buf)) {
            if (Log::get_max_level() >= Log::Level::DEBUG) {
                log_trace("Message %u to %d/%d from %u/%u discarded by incoming filters",
                          buf.curr.msg_id,
                          buf.curr.target_sysid,
                          buf.curr.target_compid,
                          buf.curr.src_sysid,
                          buf.curr.src_compid);
            }
        } else {
            _add_sys_comp_id(buf.curr.src_sysid, buf.curr.src_compid);
            Mainloop::get_instance().route_msg(&buf);
        }
    }

    return r;
}

int Endpoint::read_msg(struct buffer *pbuf)
{
    bool should_read_more = true;
    const mavlink_msg_entry_t *msg_entry;
    uint8_t *payload, seq, payload_len;
    int target_sysid, target_compid;
    uint8_t src_sysid, src_compid;
    uint32_t msg_id;

    if (fd < 0) {
        log_error("%s %s: Trying to read invalid fd", _type.c_str(), _name.c_str());
        return -EINVAL;
    }

    if (_last_packet_len != 0) {
        /*
         * read_msg() should be called in a loop after writting to each
         * output. However we don't want to keep busy looping on a single
         * endpoint reading more data. If we left data behind, move them
         * to the beginning and check we have a complete packet, but don't
         * read more data right now - it will be handled on next
         * iteration when more data is available
         */
        should_read_more = false;

        /* see TODO below about using bigger buffers: we could just walk on
         * the buffer rather than moving bytes */
        rx_buf.len -= _last_packet_len;
        if (rx_buf.len > 0) {
            memmove(rx_buf.data, rx_buf.data + _last_packet_len, rx_buf.len);
        }

        _last_packet_len = 0;
    }

    if (should_read_more) {
        ssize_t r = _read_msg(rx_buf.data + rx_buf.len, RX_BUF_MAX_SIZE - rx_buf.len);
        if (r <= 0) {
            return r;
        }

        log_trace("> %s [%d]%s: Got %zd bytes", _type.c_str(), fd, _name.c_str(), r);
        rx_buf.len += r;
    }

    bool mavlink2 = rx_buf.data[0] == MAVLINK_STX;
    bool mavlink1 = rx_buf.data[0] == MAVLINK_STX_MAVLINK1;

    /*
     * Find magic byte as the start byte:
     *
     * we either enter here due to new bytes being written to the
     * beginning of the buffer or due to _last_packet_len not being 0
     * above, which means we moved some bytes we read previously
     */
    if (!mavlink1 && !mavlink2) {
        unsigned int stx_pos = 0;

        for (unsigned int i = 1; i < (unsigned int)rx_buf.len; i++) {
            if (rx_buf.data[i] == MAVLINK_STX) {
                mavlink2 = true;
            } else if (rx_buf.data[i] == MAVLINK_STX_MAVLINK1) {
                mavlink1 = true;
            }

            if (mavlink1 || mavlink2) {
                stx_pos = i;
                break;
            }
        }

        /* Discarding data since we don't have a marker */
        if (stx_pos == 0) {
            rx_buf.len = 0;
            return 0;
        }

        /*
         * TODO: a larger buffer would allow to avoid the memmove in case a
         * new message would still fit in our buffer
         */
        rx_buf.len -= stx_pos;
        memmove(rx_buf.data, rx_buf.data + stx_pos, rx_buf.len);
    }

    const uint8_t checksum_len = 2;
    size_t expected_size;

    if (mavlink2) {
        auto *hdr = (struct mavlink_router_mavlink2_header *)rx_buf.data;

        if (rx_buf.len < sizeof(*hdr)) {
            return 0;
        }

        msg_id = hdr->msgid;
        payload = rx_buf.data + sizeof(*hdr);
        seq = hdr->seq;
        src_sysid = hdr->sysid;
        src_compid = hdr->compid;
        payload_len = hdr->payload_len;

        expected_size = sizeof(*hdr);
        expected_size += hdr->payload_len;
        expected_size += checksum_len;
        if (hdr->incompat_flags & MAVLINK_IFLAG_SIGNED) {
            expected_size += MAVLINK_SIGNATURE_BLOCK_LEN;
        }
    } else {
        auto *hdr = (struct mavlink_router_mavlink1_header *)rx_buf.data;

        if (rx_buf.len < sizeof(*hdr)) {
            return 0;
        }

        msg_id = hdr->msgid;
        payload = rx_buf.data + sizeof(*hdr);
        seq = hdr->seq;
        src_sysid = hdr->sysid;
        src_compid = hdr->compid;
        payload_len = hdr->payload_len;

        expected_size = sizeof(*hdr);
        expected_size += hdr->payload_len;
        expected_size += checksum_len;
    }

    /* check if we have a valid mavlink packet */
    if (rx_buf.len < expected_size) {
        return 0;
    }

    /* We always want to transmit one packet at a time; record the number
     * of bytes read in addition to the expected size and leave them for
     * the next iteration */
    _last_packet_len = expected_size;
    _stat.read.total++;

    msg_entry = mavlink_get_msg_entry(msg_id);
    if (msg_entry) {
        /*
         * It is accepting and forwarding unknown messages ids because
         * it can be a new MAVLink message implemented only in
         * Ground Station and Flight Stack. Although it can also be a
         * corrupted message is better forward than silent drop it.
         */
        if (!_check_crc(msg_entry)) {
            _stat.read.crc_error++;
            _stat.read.crc_error_bytes += expected_size;
            return 0;
        }
    }

    _stat.read.handled++;
    _stat.read.handled_bytes += expected_size;

    target_sysid = -1;
    target_compid = -1;

    if (msg_entry == nullptr) {
        log_trace("%s [%d]%s: No message entry for %u", _type.c_str(), fd, _name.c_str(), msg_id);
    } else {
        if (msg_entry->flags & MAV_MSG_ENTRY_FLAG_HAVE_TARGET_SYSTEM) {
            // if target_system is 0, it may have been trimmed out on mavlink2
            if (msg_entry->target_system_ofs < payload_len) {
                target_sysid = payload[msg_entry->target_system_ofs];
            } else {
                target_sysid = 0;
            }
        }
        if (msg_entry->flags & MAV_MSG_ENTRY_FLAG_HAVE_TARGET_COMPONENT) {
            // if target_system is 0, it may have been trimmed out on mavlink2
            if (msg_entry->target_component_ofs < payload_len) {
                target_compid = payload[msg_entry->target_component_ofs];
            } else {
                target_compid = 0;
            }
        }
        msg_id = msg_entry->msgid;
    }

    pbuf->curr = {msg_id, target_sysid, target_compid, src_sysid, src_compid, payload_len, payload};

    // Check for sequence drops
    if (_stat.read.expected_seq != seq) {
        if (_stat.read.total > 1) {
            uint8_t diff;

            if (seq > _stat.read.expected_seq) {
                diff = (seq - _stat.read.expected_seq);
            } else {
                diff = (UINT8_MAX - _stat.read.expected_seq) + seq;
            }

            _stat.read.drop_seq_total += diff;
            _stat.read.total += diff;
        }
        _stat.read.expected_seq = seq;
    }
    _stat.read.expected_seq++;

    pbuf->data = rx_buf.data;
    pbuf->len = expected_size;

    return msg_entry != nullptr ? ReadOk : ReadUnkownMsg;
}

void Endpoint::_add_sys_comp_id(uint8_t sysid, uint8_t compid)
{
    uint16_t sys_comp_id = ((uint16_t)sysid << 8) | compid;

    if (has_sys_comp_id(sys_comp_id)) {
        return;
    }

    if ((sniffer_sysid != 0) && ((sys_comp_id >> 8) == sniffer_sysid)) {
        log_info("Sniffer sysid %u identified. [%d] is now sniffing all messages",
                 sniffer_sysid,
                 fd);
    }
    _sys_comp_ids.push_back(sys_comp_id);

    // add to grouped endpoints as well
    for (auto e : _group_members) {
        e->_add_sys_comp_id(sysid, compid);
    }
}

bool Endpoint::has_sys_id(unsigned sysid) const
{
    for (const auto &id : _sys_comp_ids) {
        if (uint16_t(id >> 8) == (sysid & 0x00ff)) {
            return true;
        }
    }
    return false;
}

bool Endpoint::has_sys_comp_id(unsigned sys_comp_id) const
{
    for (const auto &id : _sys_comp_ids) {
        if (sys_comp_id == id) {
            return true;
        }
    }

    return false;
}

Endpoint::AcceptState Endpoint::accept_msg(const struct buffer *pbuf) const
{
    if (Log::get_max_level() >= Log::Level::TRACE) {
        log_trace("Endpoint [%d]%s: got message %u to %d/%d from %u/%u",
                  fd,
                  _name.c_str(),
                  pbuf->curr.msg_id,
                  pbuf->curr.target_sysid,
                  pbuf->curr.target_compid,
                  pbuf->curr.src_sysid,
                  pbuf->curr.src_compid);
        log_trace("\tKnown components:");
        for (const auto &id : _sys_comp_ids) {
            log_trace("\t\t%u/%u", (id >> 8), id & 0xff);
        }
    }

    // This endpoint sent the message, we don't want to send it back over the
    // same channel to avoid loops: reject
    if (has_sys_comp_id(pbuf->curr.src_sysid, pbuf->curr.src_compid)) {
        return Endpoint::AcceptState::Rejected;
    }

    // If filter is defined and message is not in the set: discard it
    if (pbuf->curr.msg_id != UINT32_MAX && !_allowed_outgoing_msg_ids.empty()
        && !vector_contains(_allowed_outgoing_msg_ids, pbuf->curr.msg_id)) {
        return Endpoint::AcceptState::Filtered;
    }

    // If filter is defined and message is in the set: discard it
    if (pbuf->curr.msg_id != UINT32_MAX && !_blocked_outgoing_msg_ids.empty()
        && vector_contains(_blocked_outgoing_msg_ids, pbuf->curr.msg_id)) {
        return Endpoint::AcceptState::Filtered;
    }

    // If filter is defined and message is not in the set: discard it
    if (pbuf->curr.msg_id != UINT32_MAX && !_allowed_outgoing_src_comps.empty()
        && !vector_contains(_allowed_outgoing_src_comps, pbuf->curr.src_compid)) {
        return Endpoint::AcceptState::Filtered;
    }

    // If filter is defined and message is in the set: discard it
    if (pbuf->curr.msg_id != UINT32_MAX && !_blocked_outgoing_src_comps.empty()
        && vector_contains(_blocked_outgoing_src_comps, pbuf->curr.src_compid)) {
        return Endpoint::AcceptState::Filtered;
    }

    // If filter is defined and message is not in the set: discard it
    if (pbuf->curr.msg_id != UINT32_MAX && !_allowed_outgoing_src_systems.empty()
        && !vector_contains(_allowed_outgoing_src_systems, pbuf->curr.src_sysid)) {
        return Endpoint::AcceptState::Filtered;
    }

    // If filter is defined and message is in the set: discard it
    if (pbuf->curr.msg_id != UINT32_MAX && !_blocked_outgoing_src_systems.empty()
        && vector_contains(_blocked_outgoing_src_systems, pbuf->curr.src_sysid)) {
        return Endpoint::AcceptState::Filtered;
    }

    // Message is broadcast on sysid or sysid is non-existent: accept msg
    if (pbuf->curr.target_sysid == 0 || pbuf->curr.target_sysid == -1) {
        return Endpoint::AcceptState::Accepted;
    }

    // This endpoint has the target of message (sys and comp id): accept
    if (pbuf->curr.target_compid > 0
        && has_sys_comp_id(pbuf->curr.target_sysid, pbuf->curr.target_compid)) {
        return Endpoint::AcceptState::Accepted;
    }

    // This endpoint has the target of message (sysid, but compid is broadcast or non-existent):
    // accept
    if ((pbuf->curr.target_compid == 0 || pbuf->curr.target_compid == -1)
        && has_sys_id(pbuf->curr.target_sysid)) {
        return Endpoint::AcceptState::Accepted;
    }
    // This endpoint has the sniffer_sysid: accept
    if ((sniffer_sysid != 0) && has_sys_id(sniffer_sysid)) {
        return Endpoint::AcceptState::Accepted;
    }

    // Reject everything else
    return Endpoint::AcceptState::Rejected;
}

bool Endpoint::allowed_by_dedup(const buffer *buf) const
{
    return Mainloop::get_instance().dedup_check_msg(buf);
}

bool Endpoint::allowed_by_incoming_filters(const buffer *buf) const
{
    // If filter is defined and message is not in the set: discard it
    if (buf->curr.msg_id != UINT32_MAX && !_allowed_incoming_msg_ids.empty()
        && !vector_contains(_allowed_incoming_msg_ids, buf->curr.msg_id)) {
        return false;
    }

    // If filter is defined and message is in the set: discard it
    if (buf->curr.msg_id != UINT32_MAX && !_blocked_incoming_msg_ids.empty()
        && vector_contains(_blocked_incoming_msg_ids, buf->curr.msg_id)) {
        return false;
    }

    // If filter is defined and message is not in the set: discard it
    if (!_allowed_incoming_src_comps.empty()
        && !vector_contains(_allowed_incoming_src_comps, buf->curr.src_compid)) {
        return false;
    }

    // If filter is defined and message is in the set: discard it
    if (!_blocked_incoming_src_comps.empty()
        && vector_contains(_blocked_incoming_src_comps, buf->curr.src_compid)) {
        return false;
    }

    // If filter is defined and message is not in the set: discard it
    if (!_allowed_incoming_src_systems.empty()
        && !vector_contains(_allowed_incoming_src_systems, buf->curr.src_sysid)) {
        return false;
    }

    // If filter is defined and message is in the set: discard it
    if (!_blocked_incoming_src_systems.empty()
        && vector_contains(_blocked_incoming_src_systems, buf->curr.src_sysid)) {
        return false;
    }

    // everything else seems to be allowed
    return true;
}

void Endpoint::link_group_member(std::shared_ptr<Endpoint> other)
{
    if (_group_name.empty() || other->get_group_name() != _group_name) {
        return;
    }

    _group_members.push_back(other);

    log_info("Grouped %s with %s", other->_name.c_str(), _name.c_str());
}

bool Endpoint::_check_crc(const mavlink_msg_entry_t *msg_entry) const
{
    const bool mavlink2 = rx_buf.data[0] == MAVLINK_STX;
    uint16_t crc_msg, crc_calc;
    uint8_t payload_len, header_len, *payload;

    if (mavlink2) {
        auto *hdr = (struct mavlink_router_mavlink2_header *)rx_buf.data;
        payload = rx_buf.data + sizeof(*hdr);
        header_len = sizeof(*hdr);
        payload_len = hdr->payload_len;
    } else {
        auto *hdr = (struct mavlink_router_mavlink1_header *)rx_buf.data;
        payload = rx_buf.data + sizeof(*hdr);
        header_len = sizeof(*hdr);
        payload_len = hdr->payload_len;
    }

    crc_msg = payload[payload_len] | (payload[payload_len + 1] << 8);
    crc_calc = crc_calculate(&rx_buf.data[1], header_len + payload_len - 1);
    crc_accumulate(msg_entry->crc_extra, &crc_calc);
    return crc_calc == crc_msg;
}

void Endpoint::print_statistics()
{
    const uint32_t read_total = _stat.read.total == 0 ? 1 : _stat.read.total;

    printf("%s Endpoint [%d]%s {", _type.c_str(), fd, _name.c_str());
    printf("\n\tReceived messages {");
    printf("\n\t\tCRC error: %u %u%% %" PRIu64 "KB",
           _stat.read.crc_error,
           (_stat.read.crc_error * 100) / read_total,
           _stat.read.crc_error_bytes / 1000);
    printf("\n\t\tSequence lost: %u %u%%",
           _stat.read.drop_seq_total,
           (_stat.read.drop_seq_total * 100) / read_total);
    printf("\n\t\tHandled: %u %" PRIu64 "KB", _stat.read.handled, _stat.read.handled_bytes / 1000);
    printf("\n\t\tTotal: %u", _stat.read.total);
    printf("\n\t}");
    printf("\n\tTransmitted messages {");
    printf("\n\t\tTotal: %u %" PRIu64 "KB", _stat.write.total, _stat.write.bytes / 1000);
    printf("\n\t}");
    printf("\n}\n");
    fflush(stdout);
}

uint8_t Endpoint::get_trimmed_zeros(const mavlink_msg_entry_t *msg_entry,
                                    const struct buffer *buffer)
{
    auto *msg = (struct mavlink_router_mavlink2_header *)buffer->data;

    /* Only MAVLink 2 trim zeros */
    if (buffer->data[0] != MAVLINK_STX) {
        return 0;
    }

    /* Should never happen but if happens it will cause stack overflow */
    if (msg->payload_len > msg_entry->max_msg_len) {
        return 0;
    }

    return msg_entry->max_msg_len - msg->payload_len;
}

void Endpoint::log_aggregate(unsigned int interval_sec)
{
    if (_incomplete_msgs > 0) {
        log_warning("%s Endpoint [%d]%s: %u incomplete messages in the last %d seconds",
                    _type.c_str(),
                    fd,
                    _name.c_str(),
                    _incomplete_msgs,
                    interval_sec);
        _incomplete_msgs = 0;
    }
}

VirtualEndpoint::VirtualEndpoint(const std::string &name,
                                 const std::string &serial_path,
                                 unsigned int serial_baudrate)
    : Endpoint{ENDPOINT_TYPE_VIRTUAL, name}
    , _serial_path{serial_path}
    , _serial_baudrate{serial_baudrate}
{
    _add_sys_comp_id(SYSTEM_ID, COMPONENT_ID);
}

bool VirtualEndpoint::start()
{
    if (_heartbeat != nullptr) {
        return true;
    }

    if (!_open_serial()) {
        return false;
    }

    _send_heartbeat();
    _heartbeat = Mainloop::get_instance().add_timeout(
        MSEC_PER_SEC,
        [](void *data) { return static_cast<VirtualEndpoint *>(data)->_heartbeat_timeout(); },
        this);

    return _heartbeat != nullptr;
}

void VirtualEndpoint::stop()
{
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }

    if (_heartbeat == nullptr) {
        return;
    }

    Mainloop::get_instance().del_timeout(_heartbeat);
    _heartbeat = nullptr;
}

bool VirtualEndpoint::_send_heartbeat()
{
    mavlink_message_t msg = {};
    uint8_t data[MAVLINK_MAX_PACKET_LEN] = {};
    struct buffer buf = {};

    mavlink_msg_heartbeat_pack(SYSTEM_ID,
                               COMPONENT_ID,
                               &msg,
                               MAV_TYPE_GENERIC,
                               MAV_AUTOPILOT_INVALID,
                               0,
                               0,
                               MAV_STATE_STANDBY);

    buf.data = data;
    buf.len = mavlink_msg_to_send_buffer(data, &msg);
    buf.curr.msg_id = msg.msgid;
    buf.curr.target_sysid = 0;
    buf.curr.target_compid = MAV_COMP_ID_ALL;
    buf.curr.src_sysid = msg.sysid;
    buf.curr.src_compid = msg.compid;
    buf.curr.payload_len = msg.len;
    buf.curr.payload = reinterpret_cast<uint8_t *>(msg.payload64);

    Mainloop::get_instance().route_msg(&buf);

    _stat.read.total++;
    _stat.read.handled++;
    _stat.read.handled_bytes += buf.len;

    return true;
}

bool VirtualEndpoint::_open_serial()
{
    if (fd >= 0) {
        return true;
    }

    fd = ::open(_serial_path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOCTTY);
    if (fd < 0) {
        log_error("VirtualEndpoint: Could not open %s (%m)", _serial_path.c_str());
        return false;
    }

    if (reset_uart(fd) < 0) {
        log_error("VirtualEndpoint: Could not reset uart on %s", _serial_path.c_str());
        ::close(fd);
        fd = -1;
        return false;
    }

    struct termios2 tc;
    bzero(&tc, sizeof(tc));

    if (ioctl(fd, TCGETS2, &tc) == -1) {
        log_error("VirtualEndpoint: Could not get termios2 on %s (%m)", _serial_path.c_str());
        ::close(fd);
        fd = -1;
        return false;
    }

    tc.c_cflag &= ~(CBAUD);
    tc.c_cflag |= BOTHER;
    tc.c_ispeed = _serial_baudrate;
    tc.c_ospeed = _serial_baudrate;

    tc.c_iflag &= ~(IGNBRK | BRKINT | ICRNL | INLCR | PARMRK | INPCK | ISTRIP | IXON);
    tc.c_oflag &= ~(OCRNL | ONLCR | ONLRET | ONOCR | OFILL | OPOST);
    tc.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | ECHONL | ICANON | IEXTEN | ISIG);
    tc.c_lflag &= ~(TOSTOP);
    tc.c_cflag &= ~(CRTSCTS);
    tc.c_cflag &= ~(CSIZE | PARENB);
    tc.c_cflag |= CLOCAL;
    tc.c_cflag |= CS8;
    tc.c_cc[VMIN] = 0;
    tc.c_cc[VTIME] = 0;

    if (ioctl(fd, TCSETS2, &tc) == -1) {
        log_error("VirtualEndpoint: Could not set terminal attributes on %s (%m)",
                  _serial_path.c_str());
        ::close(fd);
        fd = -1;
        return false;
    }

    if (ioctl(fd, TCFLSH, TCIFLUSH) == -1) {
        log_error("VirtualEndpoint: Could not flush terminal on %s (%m)", _serial_path.c_str());
        ::close(fd);
        fd = -1;
        return false;
    }

    log_info("VirtualEndpoint: Listening for GNSS NMEA on %s @ %u baud",
             _serial_path.c_str(),
             _serial_baudrate);

    return true;
}

void VirtualEndpoint::_send_message(const mavlink_message_t &msg,
                                    int target_sysid,
                                    int target_compid)
{
    uint8_t data[MAVLINK_MAX_PACKET_LEN] = {};
    struct buffer buf = {};

    buf.data = data;
    buf.len = mavlink_msg_to_send_buffer(data, &msg);
    buf.curr.msg_id = msg.msgid;
    buf.curr.target_sysid = target_sysid;
    buf.curr.target_compid = target_compid;
    buf.curr.src_sysid = msg.sysid;
    buf.curr.src_compid = msg.compid;
    buf.curr.payload_len = msg.len;
    buf.curr.payload = nullptr;

    Mainloop::get_instance().route_msg(&buf);

    _stat.read.total++;
    _stat.read.handled++;
    _stat.read.handled_bytes += buf.len;
}

void VirtualEndpoint::_send_statustext(const std::string &text, uint8_t severity)
{
    mavlink_message_t msg = {};
    char buf[51] = {};

    size_t len = text.size();
    if (len > 50) {
        len = 50;
    }
    memcpy(buf, text.c_str(), len);

    mavlink_msg_statustext_pack(SYSTEM_ID, COMPONENT_ID, &msg, severity, buf, 0, 0);
    _send_message(msg, 0, MAV_COMP_ID_ALL);
}

void VirtualEndpoint::_handle_gntxt(const std::vector<std::string> &fields)
{
    if (fields.size() < 5) {
        return;
    }

    const std::string &text = fields[4];
    _send_statustext(text, MAV_SEVERITY_INFO);
}

static bool _nmea_parse_latlon(const std::string &val,
                               const std::string &hemisphere,
                               int32_t &out_e7)
{
    if (val.empty() || hemisphere.empty()) {
        return false;
    }

    char *end = nullptr;
    double v = strtod(val.c_str(), &end);
    if (end == val.c_str()) {
        return false;
    }

    double deg = floor(v / 100.0);
    double min = v - deg * 100.0;
    double res = deg + min / 60.0;

    if (hemisphere == "S" || hemisphere == "W") {
        res = -res;
    }

    out_e7 = static_cast<int32_t>(res * 1e7);
    return true;
}

void VirtualEndpoint::_handle_gga(const std::vector<std::string> &fields)
{
    if (fields.size() < 10) {
        return;
    }

    int32_t lat = 0;
    int32_t lon = 0;
    if (!_nmea_parse_latlon(fields[2], fields[3], lat)) {
        return;
    }
    if (!_nmea_parse_latlon(fields[4], fields[5], lon)) {
        return;
    }

    int quality = atoi(fields[6].c_str());
    if (quality <= 0) {
        _fix_type = GPS_FIX_TYPE_NO_FIX;
    } else {
        _fix_type = GPS_FIX_TYPE_3D_FIX;
    }

    _lat_e7 = lat;
    _lon_e7 = lon;
    _has_position = true;

    if (!fields[7].empty()) {
        _satellites = static_cast<uint8_t>(atoi(fields[7].c_str()));
    }

    if (!fields[8].empty()) {
        double hdop = atof(fields[8].c_str());
        _hdop_x100 = static_cast<uint16_t>(hdop * 100.0);
    }

    if (!fields[9].empty()) {
        double alt = atof(fields[9].c_str());
        _alt_mm = static_cast<int32_t>(alt * 1000.0);
    }

    _send_gps_raw();
}

void VirtualEndpoint::_handle_rmc(const std::vector<std::string> &fields)
{
    if (fields.size() < 7) {
        return;
    }

    if (fields[2] != "A") {
        _fix_type = GPS_FIX_TYPE_NO_FIX;
        return;
    }

    int32_t lat = 0;
    int32_t lon = 0;
    if (!_nmea_parse_latlon(fields[3], fields[4], lat)) {
        return;
    }
    if (!_nmea_parse_latlon(fields[5], fields[6], lon)) {
        return;
    }

    _lat_e7 = lat;
    _lon_e7 = lon;
    _has_position = true;
    _fix_type = GPS_FIX_TYPE_3D_FIX;

    _send_gps_raw();
}

void VirtualEndpoint::_handle_nmea_line(const std::string &line)
{
    if (line.empty() || line[0] != '$') {
        return;
    }

    std::string payload;
    auto asterisk = line.find('*');
    if (asterisk != std::string::npos) {
        payload = line.substr(1, asterisk - 1);
    } else {
        payload = line.substr(1);
    }

    std::vector<std::string> fields;
    size_t start = 0;
    while (start <= payload.size()) {
        auto comma = payload.find(',', start);
        if (comma == std::string::npos) {
            fields.emplace_back(payload.substr(start));
            break;
        }
        fields.emplace_back(payload.substr(start, comma - start));
        start = comma + 1;
    }

    if (fields.empty()) {
        return;
    }

    const std::string &sentence = fields[0];
    if (sentence.size() >= 5 && sentence.compare(sentence.size() - 5, 5, "GNTXT") == 0) {
        _handle_gntxt(fields);
    } else if (sentence.size() >= 3 && sentence.compare(sentence.size() - 3, 3, "GGA") == 0) {
        _handle_gga(fields);
    } else if (sentence.size() >= 3 && sentence.compare(sentence.size() - 3, 3, "RMC") == 0) {
        _handle_rmc(fields);
    }
}

void VirtualEndpoint::_send_gps_raw()
{
    if (!_has_position) {
        return;
    }

    mavlink_message_t msg = {};
    uint64_t now = now_usec();

    uint16_t eph = _hdop_x100 > 0 ? _hdop_x100 : UINT16_MAX;

    mavlink_msg_gps_raw_int_pack(SYSTEM_ID,
                                 COMPONENT_ID,
                                 &msg,
                                 now,
                                 _fix_type,
                                 _lat_e7,
                                 _lon_e7,
                                 _alt_mm,
                                 eph,
                                 UINT16_MAX,
                                 UINT16_MAX,
                                 UINT16_MAX,
                                 _satellites ? _satellites : UINT8_MAX,
                                 _alt_mm,
                                 UINT32_MAX,
                                 UINT32_MAX,
                                 UINT32_MAX,
                                 UINT32_MAX,
                                 UINT16_MAX);

    _send_message(msg, 0, MAV_COMP_ID_ALL);
}

bool VirtualEndpoint::_heartbeat_timeout()
{
    return _send_heartbeat();
}

ssize_t VirtualEndpoint::_read_msg(uint8_t *, size_t)
{
    return -EAGAIN;
}

int VirtualEndpoint::write_msg(const struct buffer *pbuf)
{
    _stat.write.total++;
    _stat.write.bytes += pbuf->len;

    log_trace("%s [%d]%s: received message %u to %d/%d from %u/%u",
              _type.c_str(),
              fd,
              _name.c_str(),
              pbuf->curr.msg_id,
              pbuf->curr.target_sysid,
              pbuf->curr.target_compid,
              pbuf->curr.src_sysid,
              pbuf->curr.src_compid);

    return pbuf->len;
}

int VirtualEndpoint::handle_read()
{
    if (fd < 0) {
        return -EINVAL;
    }

    char buf[256];
    for (;;) {
        ssize_t r = ::read(fd, buf, sizeof(buf));
        if (r == -1 && errno == EAGAIN) {
            break;
        }
        if (r <= 0) {
            if (r < 0) {
                log_error("VirtualEndpoint: Error reading GNSS data (%m)");
                return -errno;
            }
            break;
        }

        _nmea_buffer.append(buf, static_cast<size_t>(r));

        size_t pos;
        while ((pos = _nmea_buffer.find('\n')) != std::string::npos) {
            std::string line = _nmea_buffer.substr(0, pos);
            _nmea_buffer.erase(0, pos + 1);
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            _handle_nmea_line(line);
        }
    }

    return 0;
}

SBusEndpoint::SBusEndpoint(const std::string &name,
                           const std::string &serial_path,
                           unsigned int serial_baudrate,
                           bool debug_channels)
    : Endpoint{ENDPOINT_TYPE_SBUS, name}
    , _serial_path{serial_path}
    , _serial_baudrate{serial_baudrate}
    , _debug_channels{debug_channels}
{
    _add_sys_comp_id(SYSTEM_ID, COMPONENT_ID);
}

bool SBusEndpoint::start()
{
    return _open_serial();
}

bool SBusEndpoint::_open_serial()
{
    if (fd >= 0) {
        return true;
    }

    fd = ::open(_serial_path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOCTTY);
    if (fd < 0) {
        log_error("SBusEndpoint: Could not open %s (%m)", _serial_path.c_str());
        return false;
    }

    if (reset_uart(fd) < 0) {
        log_error("SBusEndpoint: Could not reset uart on %s", _serial_path.c_str());
        ::close(fd);
        fd = -1;
        return false;
    }

    struct termios2 tc;
    bzero(&tc, sizeof(tc));

    if (ioctl(fd, TCGETS2, &tc) == -1) {
        log_error("SBusEndpoint: Could not get termios2 on %s (%m)", _serial_path.c_str());
        ::close(fd);
        fd = -1;
        return false;
    }

    tc.c_cflag &= ~(CBAUD);
    tc.c_cflag |= BOTHER;
    tc.c_ispeed = _serial_baudrate;
    tc.c_ospeed = _serial_baudrate;

    tc.c_iflag &= ~(IGNBRK | BRKINT | ICRNL | INLCR | PARMRK | ISTRIP | IXON | IXOFF | IXANY);
    tc.c_iflag |= INPCK;
    tc.c_oflag &= ~(OCRNL | ONLCR | ONLRET | ONOCR | OFILL | OPOST);
    tc.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | ECHONL | ICANON | IEXTEN | ISIG);
    tc.c_lflag &= ~(TOSTOP);
    tc.c_cflag &= ~(CRTSCTS | CSIZE | PARODD);
    tc.c_cflag |= CLOCAL | CREAD | CS8 | PARENB | CSTOPB;
    tc.c_cc[VMIN] = 0;
    tc.c_cc[VTIME] = 0;

    if (ioctl(fd, TCSETS2, &tc) == -1) {
        log_error("SBusEndpoint: Could not set terminal attributes on %s (%m)",
                  _serial_path.c_str());
        ::close(fd);
        fd = -1;
        return false;
    }

    if (ioctl(fd, TCFLSH, TCIFLUSH) == -1) {
        log_error("SBusEndpoint: Could not flush terminal on %s (%m)", _serial_path.c_str());
        ::close(fd);
        fd = -1;
        return false;
    }

    log_info("SBusEndpoint: Listening for SBUS on %s @ %u baud (8E2)",
             _serial_path.c_str(),
             _serial_baudrate);

    return true;
}

ssize_t SBusEndpoint::_read_msg(uint8_t *, size_t)
{
    return -EAGAIN;
}

int SBusEndpoint::write_msg(const struct buffer *pbuf)
{
    _stat.write.total++;
    _stat.write.bytes += pbuf->len;

    log_trace("SBusEndpoint [%d]%s: received message %u to %d/%d from %u/%u",
              fd,
              _name.c_str(),
              pbuf->curr.msg_id,
              pbuf->curr.target_sysid,
              pbuf->curr.target_compid,
              pbuf->curr.src_sysid,
              pbuf->curr.src_compid);

    return pbuf->len;
}

uint16_t SBusEndpoint::_sbus_to_pwm(uint16_t value) const
{
    if (value < SBUS_MIN) {
        value = SBUS_MIN;
    } else if (value > SBUS_MAX) {
        value = SBUS_MAX;
    }

    const uint32_t scaled = (uint32_t)(value - SBUS_MIN) * 1000U;
    return (uint16_t)(1000U + ((scaled + ((SBUS_MAX - SBUS_MIN) / 2U)) / (SBUS_MAX - SBUS_MIN)));
}

void SBusEndpoint::_send_rc_override(const std::array<uint16_t, 18> &channels)
{
    mavlink_message_t msg = {};
    mavlink_rc_channels_override_t rc = {};
    uint8_t data[MAVLINK_MAX_PACKET_LEN] = {};
    struct buffer buf = {};

    rc.target_system = SBUS_TARGET_SYSTEM_ID;
    rc.target_component = SBUS_TARGET_COMPONENT_ID;
    rc.chan1_raw = channels[0];
    rc.chan2_raw = channels[1];
    rc.chan3_raw = channels[2];
    rc.chan4_raw = channels[3];
    rc.chan5_raw = channels[4];
    rc.chan6_raw = channels[5];
    rc.chan7_raw = channels[6];
    rc.chan8_raw = channels[7];
    rc.chan9_raw = channels[8];
    rc.chan10_raw = channels[9];
    rc.chan11_raw = channels[10];
    rc.chan12_raw = channels[11];
    rc.chan13_raw = channels[12];
    rc.chan14_raw = channels[13];
    rc.chan15_raw = channels[14];
    rc.chan16_raw = channels[15];
    rc.chan17_raw = channels[16];
    rc.chan18_raw = channels[17];

    mavlink_msg_rc_channels_override_encode(SYSTEM_ID, COMPONENT_ID, &msg, &rc);

    buf.data = data;
    buf.len = mavlink_msg_to_send_buffer(data, &msg);
    buf.curr.msg_id = msg.msgid;
    buf.curr.target_sysid = rc.target_system;
    buf.curr.target_compid = rc.target_component;
    buf.curr.src_sysid = msg.sysid;
    buf.curr.src_compid = msg.compid;
    buf.curr.payload_len = msg.len;
    buf.curr.payload = reinterpret_cast<uint8_t *>(msg.payload64);

    Mainloop::get_instance().route_msg(&buf);

    _stat.read.total++;
    _stat.read.handled++;
    _stat.read.handled_bytes += buf.len;
}

void SBusEndpoint::_handle_frame(const std::array<uint8_t, 25> &frame)
{
    std::array<uint16_t, 18> raw_channels{};
    std::array<uint16_t, 18> channels{};
    const uint8_t flags = frame[23];

    raw_channels[0] = (uint16_t)((((uint16_t)frame[1]) | ((uint16_t)frame[2] << 8)) & 0x07ffU);
    raw_channels[1] = (uint16_t)((((uint16_t)frame[2] >> 3) | ((uint16_t)frame[3] << 5)) & 0x07ffU);
    raw_channels[2] = (uint16_t)((((uint16_t)frame[3] >> 6) | ((uint16_t)frame[4] << 2)
                                  | ((uint16_t)frame[5] << 10))
                                 & 0x07ffU);
    raw_channels[3] = (uint16_t)((((uint16_t)frame[5] >> 1) | ((uint16_t)frame[6] << 7)) & 0x07ffU);
    raw_channels[4] = (uint16_t)((((uint16_t)frame[6] >> 4) | ((uint16_t)frame[7] << 4)) & 0x07ffU);
    raw_channels[5] = (uint16_t)((((uint16_t)frame[7] >> 7) | ((uint16_t)frame[8] << 1)
                                  | ((uint16_t)frame[9] << 9))
                                 & 0x07ffU);
    raw_channels[6] = (uint16_t)((((uint16_t)frame[9] >> 2) | ((uint16_t)frame[10] << 6)) & 0x07ffU);
    raw_channels[7]
        = (uint16_t)((((uint16_t)frame[10] >> 5) | ((uint16_t)frame[11] << 3)) & 0x07ffU);
    raw_channels[8]
        = (uint16_t)((((uint16_t)frame[12]) | ((uint16_t)frame[13] << 8)) & 0x07ffU);
    raw_channels[9]
        = (uint16_t)((((uint16_t)frame[13] >> 3) | ((uint16_t)frame[14] << 5)) & 0x07ffU);
    raw_channels[10] = (uint16_t)((((uint16_t)frame[14] >> 6) | ((uint16_t)frame[15] << 2)
                                   | ((uint16_t)frame[16] << 10))
                                  & 0x07ffU);
    raw_channels[11] = (uint16_t)((((uint16_t)frame[16] >> 1) | ((uint16_t)frame[17] << 7))
                                  & 0x07ffU);
    raw_channels[12] = (uint16_t)((((uint16_t)frame[17] >> 4) | ((uint16_t)frame[18] << 4))
                                  & 0x07ffU);
    raw_channels[13] = (uint16_t)((((uint16_t)frame[18] >> 7) | ((uint16_t)frame[19] << 1)
                                   | ((uint16_t)frame[20] << 9))
                                  & 0x07ffU);
    raw_channels[14] = (uint16_t)((((uint16_t)frame[20] >> 2) | ((uint16_t)frame[21] << 6))
                                  & 0x07ffU);
    raw_channels[15] = (uint16_t)((((uint16_t)frame[21] >> 5) | ((uint16_t)frame[22] << 3))
                                  & 0x07ffU);
    raw_channels[16] = (flags & 0x01U) ? SBUS_MAX : SBUS_MIN;
    raw_channels[17] = (flags & 0x02U) ? SBUS_MAX : SBUS_MIN;

    for (size_t i = 0; i < channels.size(); i++) {
        channels[i] = _sbus_to_pwm(raw_channels[i]);
    }

    if (_debug_channels) {
        printf("SBUS channels:");
        for (const auto channel : channels) {
            printf(" %u", channel);
        }
        printf(" | frame_lost=%u failsafe=%u\n", (flags & 0x04U) ? 1U : 0U, (flags & 0x08U) ? 1U : 0U);
        fflush(stdout);
    }

    _send_rc_override(channels);
}

bool SBusEndpoint::_parse_stream()
{
    auto start_it = std::find(_stream_buffer.begin(), _stream_buffer.end(), SBUS_START_BYTE);

    if (start_it == _stream_buffer.end()) {
        _stream_buffer.clear();
        return false;
    }

    if (start_it != _stream_buffer.begin()) {
        _stream_buffer.erase(_stream_buffer.begin(), start_it);
    }

    if (_stream_buffer.size() < 25U) {
        return false;
    }

    const uint8_t frame_end = _stream_buffer[24];
    if (frame_end != SBUS_END_BYTE && frame_end != SBUS_END_BYTE_ALT_1
        && frame_end != SBUS_END_BYTE_ALT_2 && frame_end != SBUS_END_BYTE_ALT_3) {
        _stream_buffer.erase(_stream_buffer.begin());
        return true;
    }

    std::array<uint8_t, 25> frame{};
    std::copy_n(_stream_buffer.begin(), frame.size(), frame.begin());
    _stream_buffer.erase(
        _stream_buffer.begin(),
        _stream_buffer.begin() + static_cast<std::vector<uint8_t>::difference_type>(frame.size()));

    _handle_frame(frame);
    return true;
}

int SBusEndpoint::handle_read()
{
    if (fd < 0) {
        return -EINVAL;
    }

    uint8_t buf[128];
    for (;;) {
        ssize_t r = ::read(fd, buf, sizeof(buf));
        if (r == -1 && errno == EAGAIN) {
            break;
        }
        if (r <= 0) {
            if (r < 0) {
                log_error("SBusEndpoint: Error reading SBUS data (%m)");
                return -errno;
            }
            break;
        }

        _stream_buffer.insert(_stream_buffer.end(), buf, buf + static_cast<size_t>(r));
        while (_parse_stream()) {
            ;
        }
    }

    return 0;
}

UartEndpoint::UartEndpoint(std::string name)
    : Endpoint{ENDPOINT_TYPE_UART, std::move(name)}
{
    // nothing else to do here
}

bool UartEndpoint::setup(UartEndpointConfig conf)
{
    if (!this->validate_config(conf)) {
        return false;
    }

    if (!this->open(conf.device.c_str())) {
        return false;
    }

    if (conf.baudrates.size() == 1) {
        if (this->set_speed(conf.baudrates[0]) < 0) {
            return false;
        }
    } else {
        if (this->add_speeds(conf.baudrates) < 0) {
            return false;
        }
    }

    if (conf.flowcontrol) {
        if (this->set_flow_control(true) < 0) {
            return false;
        }
    }

    for (auto msg_id : conf.allow_msg_id_out) {
        this->filter_add_allowed_out_msg_id(msg_id);
    }
    for (auto msg_id : conf.block_msg_id_out) {
        this->filter_add_blocked_out_msg_id(msg_id);
    }
    for (auto src_comp : conf.allow_src_comp_out) {
        this->filter_add_allowed_out_src_comp(src_comp);
    }
    for (auto src_comp : conf.block_src_comp_out) {
        this->filter_add_blocked_out_src_comp(src_comp);
    }
    for (auto src_sys : conf.allow_src_sys_out) {
        this->filter_add_allowed_out_src_sys(src_sys);
    }
    for (auto src_sys : conf.block_src_sys_out) {
        this->filter_add_blocked_out_src_sys(src_sys);
    }

    for (auto msg_id : conf.allow_msg_id_in) {
        this->filter_add_allowed_in_msg_id(msg_id);
    }
    for (auto msg_id : conf.block_msg_id_in) {
        this->filter_add_blocked_in_msg_id(msg_id);
    }
    for (auto src_comp : conf.allow_src_comp_in) {
        this->filter_add_allowed_in_src_comp(src_comp);
    }
    for (auto src_comp : conf.block_src_comp_in) {
        this->filter_add_blocked_in_src_comp(src_comp);
    }
    for (auto src_sys : conf.allow_src_sys_in) {
        this->filter_add_allowed_in_src_sys(src_sys);
    }
    for (auto src_sys : conf.block_src_sys_in) {
        this->filter_add_blocked_in_src_sys(src_sys);
    }

    this->_group_name = conf.group;

    return true;
}

int UartEndpoint::set_speed(speed_t baudrate)
{
    struct termios2 tc;

    if (fd < 0) {
        return -1;
    }

    bzero(&tc, sizeof(tc));
    if (ioctl(fd, TCGETS2, &tc) == -1) {
        log_error("UART [%d]%s: Could not get termios2 (%m)", fd, _name.c_str());
        return -1;
    }

    /* speed is configured by c_[io]speed */
    tc.c_cflag &= ~CBAUD;
    tc.c_cflag |= BOTHER;
    tc.c_ispeed = baudrate;
    tc.c_ospeed = baudrate;

    if (ioctl(fd, TCSETS2, &tc) == -1) {
        log_error("Could not set terminal attributes (%m)");
        return -1;
    }

    log_info("UART [%d]%s: speed = %u", fd, _name.c_str(), baudrate);

    if (ioctl(fd, TCFLSH, TCIOFLUSH) == -1) {
        log_error("UART [%d]%s: Could not flush terminal (%m)", fd, _name.c_str());
        return -1;
    }

    return 0;
}

int UartEndpoint::set_flow_control(bool enabled)
{
    struct termios2 tc;

    if (fd < 0) {
        return -1;
    }

    bzero(&tc, sizeof(tc));
    if (ioctl(fd, TCGETS2, &tc) == -1) {
        log_error("UART [%d]%s: Could not get termios2 (%m)", fd, _name.c_str());
        return -1;
    }

    if (enabled) {
        tc.c_cflag |= CRTSCTS;
    } else {
        tc.c_cflag &= ~CRTSCTS;
    }

    if (ioctl(fd, TCSETS2, &tc) == -1) {
        log_error("UART [%d]%s: Could not set terminal attributes (%m)", fd, _name.c_str());
        return -1;
    }

    log_info("UART [%d]%s: flowcontrol = %s", fd, _name.c_str(), enabled ? "enabled" : "disabled");

    return 0;
}

bool UartEndpoint::open(const char *path)
{
    struct termios2 tc;

    fd = ::open(path, O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOCTTY);
    if (fd < 0) {
        log_error("Could not open %s (%m)", path);
        return false;
    }

    if (reset_uart(fd) < 0) {
        log_error("Could not reset uart on %s", path);
        goto fail;
    }

    bzero(&tc, sizeof(tc));

    if (ioctl(fd, TCGETS2, &tc) == -1) {
        log_error("Could not get termios2 on %s (%m)", path);
        goto fail;
    }

    tc.c_iflag &= ~(IGNBRK | BRKINT | ICRNL | INLCR | PARMRK | INPCK | ISTRIP | IXON);
    tc.c_oflag &= ~(OCRNL | ONLCR | ONLRET | ONOCR | OFILL | OPOST);

    tc.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | ECHONL | ICANON | IEXTEN | ISIG);

    /* never send SIGTTOU*/
    tc.c_lflag &= ~(TOSTOP);

    /* disable flow control */
    tc.c_cflag &= ~(CRTSCTS);
    tc.c_cflag &= ~(CSIZE | PARENB);

    /* ignore modem control lines */
    tc.c_cflag |= CLOCAL;

    /* 8 bits */
    tc.c_cflag |= CS8;

    /* we use epoll to get notification of available bytes */
    tc.c_cc[VMIN] = 0;
    tc.c_cc[VTIME] = 0;

    if (ioctl(fd, TCSETS2, &tc) == -1) {
        log_error("Could not set terminal attributes on %s (%m)", path);
        goto fail;
    }

    // For Linux, set high speed polling at the chip
    // level. Since this routine relies on a USB latency
    // change at the chip level it may fail on certain
    // chip sets if their driver does not support this
    // configuration request

    {
        struct serial_struct serial_ctl;

        int result = ioctl(fd, TIOCGSERIAL, &serial_ctl);
        if (result < 0) {
            log_warning("Error while trying to read serial port configuration on %s: %m", path);
            goto set_latency_failed;
        }

        serial_ctl.flags |= ASYNC_LOW_LATENCY;

        result = ioctl(fd, TIOCSSERIAL, &serial_ctl);
        if (result < 0) {
            if (errno != ENODEV && errno != ENOTTY) {
                log_warning("Error while trying to write serial port latency on %s: %m", path);
            }
        }
    }

set_latency_failed:
    if (ioctl(fd, TCFLSH, TCIOFLUSH) == -1) {
        log_error("Could not flush terminal on %s (%m)", path);
        goto fail;
    }

    log_info("Opened UART [%d]%s: %s", fd, _name.c_str(), path);

    return true;

fail:
    ::close(fd);
    fd = -1;
    return false;
}

bool UartEndpoint::_change_baud_cb(void *data)
{
    _current_baud_idx = (_current_baud_idx + 1) % _baudrates.size();

    log_info("Retrying UART [%d]%s on new baudrate: %u",
             fd,
             _name.c_str(),
             _baudrates[_current_baud_idx]);

    set_speed(_baudrates[_current_baud_idx]);

    return true;
}

int UartEndpoint::read_msg(struct buffer *pbuf)
{
    int ret = Endpoint::read_msg(pbuf);

    if (_change_baud_timeout != nullptr && ret == ReadOk) {
        log_info("%s [%d]%s: Baudrate %u responded, keeping it",
                 _type.c_str(),
                 fd,
                 _name.c_str(),
                 _baudrates[_current_baud_idx]);
        Mainloop::get_instance().del_timeout(_change_baud_timeout);
        _change_baud_timeout = nullptr;
    }

    return ret;
}

ssize_t UartEndpoint::_read_msg(uint8_t *buf, size_t len)
{
    ssize_t r = ::read(fd, buf, len);
    if ((r == -1 && errno == EAGAIN) || r == 0) {
        return 0;
    }
    if (r == -1) {
        return -errno;
    }

    return r;
}

int UartEndpoint::write_msg(const struct buffer *pbuf)
{
    if (fd < 0) {
        log_error("UART %s: Trying to write invalid fd", _name.c_str());
        return -EINVAL;
    }

    /* TODO: send any pending data */
    if (tx_buf.len > 0) {
        ;
    }

    ssize_t r = ::write(fd, pbuf->data, pbuf->len);
    if (r == -1 && errno == EAGAIN) {
        return -EAGAIN;
    }

    _stat.write.total++;
    _stat.write.bytes += pbuf->len;

    /* Incomplete packet, we warn and discard the rest */
    if (r != (ssize_t)pbuf->len) {
        _incomplete_msgs++;
        log_debug("UART %s: Discarding packet, incomplete write %zd but len=%u",
                  _name.c_str(),
                  r,
                  pbuf->len);
    }

    log_trace("UART [%d]%s: Wrote %zd bytes", fd, _name.c_str(), r);

    return r;
}

int UartEndpoint::add_speeds(const std::vector<speed_t> &bauds)
{
    if (bauds.empty()) {
        return -EINVAL;
    }

    _baudrates = bauds;

    set_speed(_baudrates[0]);

    _change_baud_timeout = Mainloop::get_instance().add_timeout(
        MSEC_PER_SEC * UART_BAUD_RETRY_SEC,
        std::bind(&UartEndpoint::_change_baud_cb, this, std::placeholders::_1),
        this);

    return 0;
}

bool UartEndpoint::validate_config(const UartEndpointConfig &config)
{
    if (config.baudrates.empty()) {
        log_error("UartEndpoint %s: Baudrate list must not be empty", config.name.c_str());
        return false;
    }

    if (config.device.empty()) {
        log_error("UartEndpoint %s: Device must be specified", config.name.c_str());
        return false;
    }

    return true;
}

UdpEndpoint::UdpEndpoint(std::string name)
    : Endpoint{ENDPOINT_TYPE_UDP, std::move(name)}
{
    bzero(&sockaddr, sizeof(sockaddr));
    bzero(&sockaddr6, sizeof(sockaddr6));
}

UdpEndpoint::~UdpEndpoint()
{
    if (nomessage_timeout) {
        Mainloop::get_instance().del_timeout(nomessage_timeout);
    }
}

bool UdpEndpoint::setup(UdpEndpointConfig conf)
{
    if (!this->validate_config(conf)) {
        return false;
    }

    if (!this->open(conf.address.c_str(), conf.port, conf.mode)) {
        log_error("Could not open %s:%ld", conf.address.c_str(), conf.port);
        return false;
    }

    for (auto msg_id : conf.allow_msg_id_out) {
        this->filter_add_allowed_out_msg_id(msg_id);
    }
    for (auto msg_id : conf.block_msg_id_out) {
        this->filter_add_blocked_out_msg_id(msg_id);
    }
    for (auto src_comp : conf.allow_src_comp_out) {
        this->filter_add_allowed_out_src_comp(src_comp);
    }
    for (auto src_comp : conf.block_src_comp_out) {
        this->filter_add_blocked_out_src_comp(src_comp);
    }
    for (auto src_sys : conf.allow_src_sys_out) {
        this->filter_add_allowed_out_src_sys(src_sys);
    }
    for (auto src_sys : conf.block_src_sys_out) {
        this->filter_add_blocked_out_src_sys(src_sys);
    }

    for (auto msg_id : conf.allow_msg_id_in) {
        this->filter_add_allowed_in_msg_id(msg_id);
    }
    for (auto msg_id : conf.block_msg_id_in) {
        this->filter_add_blocked_in_msg_id(msg_id);
    }
    for (auto src_comp : conf.allow_src_comp_in) {
        this->filter_add_allowed_in_src_comp(src_comp);
    }
    for (auto src_comp : conf.block_src_comp_in) {
        this->filter_add_blocked_in_src_comp(src_comp);
    }
    for (auto src_sys : conf.allow_src_sys_in) {
        this->filter_add_allowed_in_src_sys(src_sys);
    }
    for (auto src_sys : conf.block_src_sys_in) {
        this->filter_add_blocked_in_src_sys(src_sys);
    }

    this->_group_name = conf.group;

    return true;
}

int UdpEndpoint::open_ipv6(const char *ip, unsigned long port, UdpEndpointConfig::Mode mode)
{
    fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) {
        log_error("Could not create IPv6 socket for %s:%lu (%m)", ip, port);
        return -errno;
    }

    /* strip square brackets from ip string */
    char *ip_str = strdup(&ip[1]);
    ip_str[strlen(ip_str) - 1] = '\0';

    /* remove omittable zeros from IPv6 address */
    sockaddr_in6 ip_addr;
    inet_pton(AF_INET6, ip_str, &ip_addr.sin6_addr);
    inet_ntop(AF_INET6, &(ip_addr.sin6_addr), ip_str, strlen(ip));

    sockaddr6.sin6_family = AF_INET6;
    sockaddr6.sin6_port = htons(port);

    /* multicast address needs to listen to all, but "filter" incoming packets */
    if (mode == UdpEndpointConfig::Mode::Server && ipv6_is_multicast(ip_str)) {
        sockaddr6.sin6_addr = in6addr_any;

        struct ipv6_mreq group;
        inet_pton(AF_INET6, ip_str, &group.ipv6mr_multiaddr);
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &group, sizeof(group)) < 0) {
            log_error("Error setting IPv6 multicast socket options for [%s]:%lu (%m)",
                      ip_str,
                      port);
            goto fail;
        }
    } else {
        inet_pton(AF_INET6, ip_str, &sockaddr6.sin6_addr);
    }

    /* link-local address needs a scope ID */
    if (ipv6_is_linklocal(ip_str)) {
        sockaddr6.sin6_scope_id = ipv6_get_scope_id(ip_str);
    }

    if (mode == UdpEndpointConfig::Mode::Server) {
        if (bind(fd, (struct sockaddr *)&sockaddr6, sizeof(sockaddr6)) < 0) {
            log_error("Error binding IPv6 socket for [%s]:%lu (%m)", ip_str, port);
            goto fail;
        }
        sockaddr6.sin6_port = 0;
    }

    config_sock.v6 = sockaddr6;

    free(ip_str);
    return fd;

fail:
    free(ip_str);
    ::close(fd);
    fd = -1;
    return -EINVAL;
}

int UdpEndpoint::open_ipv4(const char *ip, unsigned long port, UdpEndpointConfig::Mode mode)
{
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        log_error("Could not create IPv4 socket for %s:%lu (%m)", ip, port);
        return -errno;
    }

    sockaddr.sin_family = AF_INET;
    sockaddr.sin_addr.s_addr = inet_addr(ip);
    sockaddr.sin_port = htons(port);

    if (mode == UdpEndpointConfig::Mode::Server) {
        if (bind(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
            log_error("Error binding IPv4 socket for %s:%lu (%m)", ip, port);
            goto fail;
        }
        sockaddr.sin_port = 0;
    }

    config_sock.v4 = sockaddr;

    return fd;

fail:
    ::close(fd);
    fd = -1;
    return -EINVAL;
}

bool UdpEndpoint::open(const char *ip, unsigned long port, UdpEndpointConfig::Mode mode)
{
    const int broadcast_val = 1;

    this->is_ipv6 = ip_str_is_ipv6(ip);

    // setup the special IPv6/IPv4 part
    if (this->is_ipv6) {
        open_ipv6(ip, port, mode);
    } else {
        open_ipv4(ip, port, mode);
    }

    if (fd < 0) {
        return false;
    }

    // common setup
    if (mode == UdpEndpointConfig::Mode::Client) {
        if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &broadcast_val, sizeof(broadcast_val))) {
            log_error("Error enabling broadcast in socket for %s:%lu (%m)", ip, port);
            goto fail;
        }

        // Disarmed timeout: we will arm it when we receive a message
        nomessage_timeout = Mainloop::get_instance().add_timeout(
            0,
            std::bind(&UdpEndpoint::_nomessage_timeout_cb, this, std::placeholders::_1),
            nullptr);
    }

    if (fcntl(fd, F_SETFL, O_NONBLOCK | FASYNC) < 0) {
        log_error("Error setting socket fd as non-blocking for %s:%lu (%m)", ip, port);
        goto fail;
    }

    if (mode == UdpEndpointConfig::Mode::Server) {
        log_info("Opened UDP Server [%d]%s: %s:%lu", fd, _name.c_str(), ip, port);
    } else {
        log_info("Opened UDP Client [%d]%s: %s:%lu", fd, _name.c_str(), ip, port);
    }

    return true;

fail:
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
    return false;
}

bool UdpEndpoint::_nomessage_timeout_cb(void *data)
{
    Mainloop::get_instance().mod_timeout(nomessage_timeout, 0);
    bool change = false;

    if (this->is_ipv6) {
        change = memcmp(&sockaddr6, &config_sock.v6, sizeof(sockaddr6)) != 0;
        sockaddr6 = config_sock.v6;
    } else {
        change = memcmp(&sockaddr, &config_sock.v4, sizeof(sockaddr)) != 0;
        sockaddr = config_sock.v4;
    }

    if (change) {
        log_error("No messages on [%d]%s: switching back to broadcast", fd, _name.c_str());
    }

    return true;
}

ssize_t UdpEndpoint::_read_msg(uint8_t *buf, size_t len)
{
    socklen_t addrlen;
    struct sockaddr *sock;
    ssize_t r = 0;

    if (this->is_ipv6) {
        addrlen = sizeof(sockaddr6);
        sock = (struct sockaddr *)&sockaddr6;
    } else {
        addrlen = sizeof(sockaddr);
        sock = (struct sockaddr *)&sockaddr;
    }

    r = ::recvfrom(fd, buf, len, 0, sock, &addrlen);
    if (r == -1 && errno == EAGAIN) {
        return 0;
    }
    if (r == -1) {
        return -errno;
    }

    // Update timeout
    if (nomessage_timeout) {
        Mainloop::get_instance().mod_timeout(nomessage_timeout, 5 * MSEC_PER_SEC);
    }

    return r;
}

int UdpEndpoint::write_msg(const struct buffer *pbuf)
{
    struct sockaddr *sock;
    socklen_t addrlen;

    if (fd < 0) {
        log_error("UDP %s: Trying to write invalid fd", _name.c_str());
        return -EINVAL;
    }

    /* TODO: send any pending data */
    if (tx_buf.len > 0) {
        ;
    }

    bool sock_connected = false;
    if (this->is_ipv6) {
        addrlen = sizeof(sockaddr6);
        sock = (struct sockaddr *)&sockaddr6;
        sock_connected = sockaddr6.sin6_port != 0;
    } else {
        addrlen = sizeof(sockaddr);
        sock = (struct sockaddr *)&sockaddr;
        sock_connected = sockaddr.sin_port != 0;
    }

    if (!sock_connected) {
        log_trace("UDP %s: No one ever connected to us. No one to write for", _name.c_str());
        return 0;
    }

    ssize_t r = ::sendto(fd, pbuf->data, pbuf->len, 0, sock, addrlen);
    if (r == -1) {
        if (errno != EAGAIN && errno != ECONNREFUSED && errno != ENETUNREACH) {
            log_error("UDP %s: Error sending udp packet (%m)", _name.c_str());
        }
        return -errno;
    };

    _stat.write.total++;
    _stat.write.bytes += pbuf->len;

    /* Incomplete packet, we warn and discard the rest */
    if (r != (ssize_t)pbuf->len) {
        _incomplete_msgs++;
        log_debug("UDP %s: Discarding packet, incomplete write %zd but len=%u",
                  _name.c_str(),
                  r,
                  pbuf->len);
    }

    log_trace("UDP [%d]%s: Wrote %zd bytes", fd, _name.c_str(), r);

    return r;
}

int UdpEndpoint::parse_udp_mode(const char *val, size_t val_len, void *storage, size_t storage_len)
{
    assert(val);
    assert(storage);
    assert(val_len);

    if (storage_len < sizeof(bool)) {
        return -ENOBUFS;
    }
    if (val_len > INT_MAX) {
        return -EINVAL;
    }

    auto *udp_mode = (UdpEndpointConfig::Mode *)storage;
    if (memcaseeq(val, val_len, "normal", sizeof("normal") - 1)) {
        *udp_mode = UdpEndpointConfig::Mode::Client;
    } else if (memcaseeq(val, val_len, "eavesdropping", sizeof("eavesdropping") - 1)) {
        log_warning("Eavesdropping mode is deprecated and rather act like udpin/server");
        *udp_mode = UdpEndpointConfig::Mode::Server;
    } else if (memcaseeq(val, val_len, "server", sizeof("server") - 1)) {
        *udp_mode = UdpEndpointConfig::Mode::Server;
    } else {
        log_error("Unknown 'mode' key: %.*s", (int)val_len, val);
        return -EINVAL;
    }

    return 0;
}

bool UdpEndpoint::validate_config(const UdpEndpointConfig &config)
{
    if (config.address.empty()) {
        log_error("UdpEndpoint %s: IP address must be specified", config.name.c_str());
        return false;
    }

    if (!validate_ip(config.address)) {
        log_error("UdpEndpoint %s: Invalid IP address %s",
                  config.name.c_str(),
                  config.address.c_str());
        return false;
    }

    if (config.port == 0 || config.port == ULONG_MAX) {
        log_error("UdpEndpoint %s: Invalid or unset UDP port %lu",
                  config.name.c_str(),
                  config.port);
        return false;
    }

    if (config.mode != UdpEndpointConfig::Mode::Client
        && config.mode != UdpEndpointConfig::Mode::Server) {
        return false;
    }

    return true;
}

TcpEndpoint::TcpEndpoint(std::string name)
    : Endpoint{ENDPOINT_TYPE_TCP, std::move(name)}
{
    bzero(&sockaddr, sizeof(sockaddr));
    bzero(&sockaddr6, sizeof(sockaddr6));
}

TcpEndpoint::~TcpEndpoint()
{
    close();
}

bool TcpEndpoint::setup(TcpEndpointConfig conf)
{
    if (!this->validate_config(conf)) {
        return false;
    }

    this->_ip = conf.address;
    this->_port = conf.port;
    this->_retry_timeout = conf.retry_timeout;

    for (auto msg_id : conf.allow_msg_id_out) {
        this->filter_add_allowed_out_msg_id(msg_id);
    }
    for (auto msg_id : conf.block_msg_id_out) {
        this->filter_add_blocked_out_msg_id(msg_id);
    }
    for (auto src_comp : conf.allow_src_comp_out) {
        this->filter_add_allowed_out_src_comp(src_comp);
    }
    for (auto src_comp : conf.block_src_comp_out) {
        this->filter_add_blocked_out_src_comp(src_comp);
    }
    for (auto src_sys : conf.allow_src_sys_out) {
        this->filter_add_allowed_out_src_sys(src_sys);
    }
    for (auto src_sys : conf.block_src_sys_out) {
        this->filter_add_blocked_out_src_sys(src_sys);
    }

    for (auto msg_id : conf.allow_msg_id_in) {
        this->filter_add_allowed_in_msg_id(msg_id);
    }
    for (auto msg_id : conf.block_msg_id_in) {
        this->filter_add_blocked_in_msg_id(msg_id);
    }
    for (auto src_comp : conf.allow_src_comp_in) {
        this->filter_add_allowed_in_src_comp(src_comp);
    }
    for (auto src_comp : conf.block_src_comp_in) {
        this->filter_add_blocked_in_src_comp(src_comp);
    }
    for (auto src_sys : conf.allow_src_sys_in) {
        this->filter_add_allowed_in_src_sys(src_sys);
    }
    for (auto src_sys : conf.block_src_sys_in) {
        this->filter_add_blocked_in_src_sys(src_sys);
    }

    this->_group_name = conf.group;

    if (!this->open(conf.address, conf.port)) {
        log_warning("Could not open %s:%ld, re-trying every %d sec",
                    conf.address.c_str(),
                    conf.port,
                    this->_retry_timeout);
        if (this->_retry_timeout > 0) {
            _schedule_reconnect();
        }
        return true;
    }

    return true;
}

bool TcpEndpoint::reopen()
{
    return this->open(_ip, _port);
}

int TcpEndpoint::accept(int listener_fd)
{
    struct sockaddr *sock;
    socklen_t addrlen;

    this->_retry_timeout = 0; // disable reconnect for incoming TCP server connections
    this->is_ipv6 = false;    // TCP server is IPv4 only for now

    if (this->is_ipv6) {
        addrlen = sizeof(sockaddr6);
        sock = (struct sockaddr *)&sockaddr6;
    } else {
        addrlen = sizeof(sockaddr);
        sock = (struct sockaddr *)&sockaddr;
    }

    fd = accept4(listener_fd, sock, &addrlen, SOCK_NONBLOCK);
    if (fd == -1) {
        return -1;
    }

    log_info("TCP [%d]%s: Connection accepted", fd, _name.c_str());

    int tcp_nodelay_state = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&tcp_nodelay_state, sizeof(int)) < 0) {
        log_error("Error setting TCP_NODELAY on [%d]%s", fd, _name.c_str());
        return -1;
    }

    return fd;
}

int TcpEndpoint::open_ipv6(const char *ip, unsigned long port, sockaddr_in6 &sockaddr6)
{
    auto fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd == -1) {
        log_error("Could not create IPv6 socket for %s:%lu (%m)", ip, port);
        return -1;
    }

    /* strip square brackets from ip string */
    char *ip_str = strdup(&ip[1]);
    ip_str[strlen(ip_str) - 1] = '\0';

    /* multicast address is not allowed for TCP sockets */
    if (ipv6_is_multicast(ip_str)) {
        log_error("TCP endpoints do not support multicast address");
        goto fail;
    }

    sockaddr6.sin6_family = AF_INET6;
    sockaddr6.sin6_port = htons(port);
    inet_pton(AF_INET6, ip_str, &sockaddr6.sin6_addr);

    /* link-local address needs a scope ID */
    if (ipv6_is_linklocal(ip_str)) {
        sockaddr6.sin6_scope_id = ipv6_get_scope_id(ip_str);
    }

    free(ip_str);

    return fd;

fail:
    free(ip_str);
    fd = -1;
    return fd;
}

int TcpEndpoint::open_ipv4(const char *ip, unsigned long port, sockaddr_in &sockaddr)
{
    auto fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        log_error("Could not create IPv4 socket for %s:%lu (%m)", ip, port);
        return -1;
    }

    sockaddr.sin_family = AF_INET;
    sockaddr.sin_addr.s_addr = inet_addr(ip);
    sockaddr.sin_port = htons(port);

    return fd;
}

bool TcpEndpoint::open(const std::string &ip, unsigned long port)
{
    this->is_ipv6 = ip_str_is_ipv6(ip.c_str());

    // setup the special IPv6/IPv4 part
    struct sockaddr *sock;
    socklen_t addrlen;
    if (this->is_ipv6) {
        fd = open_ipv6(ip.c_str(), port, this->sockaddr6);
        sock = (struct sockaddr *)&this->sockaddr6;
        addrlen = sizeof(sockaddr6);
    } else {
        fd = open_ipv4(ip.c_str(), port, this->sockaddr);
        sock = (struct sockaddr *)&this->sockaddr;
        addrlen = sizeof(sockaddr);
    }

    if (fd < 0) {
        return false;
    }

    // common setup
    if (connect(fd, sock, addrlen) < 0) {
        log_error("%d Error connecting to %s:%lu (%m)", fd, ip.c_str(), port);
        goto fail;
    }

    if (fcntl(fd, F_SETFL, O_NONBLOCK | FASYNC) < 0) {
        log_error("Error setting socket fd as non-blocking for %s:%lu (%m)", ip.c_str(), port);
        goto fail;
    }

    log_info("Opened TCP Client [%d]%s: %s:%lu", fd, _name.c_str(), ip.c_str(), port);

    _valid = true;
    return true;

fail:
    ::close(fd);
    fd = -1;
    return false;
}

ssize_t TcpEndpoint::_read_msg(uint8_t *buf, size_t len)
{
    struct sockaddr *sock;
    socklen_t addrlen;
    ssize_t r;

    if (this->is_ipv6) {
        sock = (struct sockaddr *)&sockaddr6;
        addrlen = sizeof(sockaddr6);
    } else {
        sock = (struct sockaddr *)&sockaddr;
        addrlen = sizeof(sockaddr);
    }

    r = ::recvfrom(fd, buf, len, 0, sock, &addrlen);
    if (r == -1 && errno == EAGAIN) {
        return 0;
    }
    if (r == -1) {
        return -errno;
    }

    // a read of zero on a stream socket means that other side shut down
    if (r == 0 && len != 0) {
        if (_retry_timeout > 0) {
            this->_schedule_reconnect();
            _valid = true; // still valid, b/c endpoint handles reconnect internally
        } else {
            _valid = false; // client connection can be deleted forever
        }
        return EOF; // TODO is EOF always negative?
    }

    return r;
}

int TcpEndpoint::write_msg(const struct buffer *pbuf)
{
    struct sockaddr *sock;
    socklen_t addrlen;

    if (fd < 0) {
        // skip this endpoint if not connected (e.g. during reconnect)
        return 0;
    }

    /* TODO: send any pending data */
    if (tx_buf.len > 0) {
        ;
    }

    if (this->is_ipv6) {
        sock = (struct sockaddr *)&sockaddr6;
        addrlen = sizeof(sockaddr6);
    } else {
        sock = (struct sockaddr *)&sockaddr;
        addrlen = sizeof(sockaddr);
    }

    ssize_t r = ::sendto(fd, pbuf->data, pbuf->len, 0, sock, addrlen);
    if (r == -1) {
        if (errno != EAGAIN && errno != ECONNREFUSED) {
            log_error("TCP %s: Error sending tcp packet (%m)", _name.c_str());
        }
        if (errno == EPIPE) {
            if (_retry_timeout > 0) {
                this->_schedule_reconnect();
                _valid = true; // still valid, b/c endpoint handles reconnect internally
            } else {
                _valid = false; // client connection can be deleted forever
            }
        }
        return -errno;
    };

    _stat.write.total++;
    _stat.write.bytes += pbuf->len;

    /* Incomplete packet, we warn and discard the rest */
    if (r != (ssize_t)pbuf->len) {
        _incomplete_msgs++;
        log_debug("TCP %s: Discarding packet, incomplete write %zd but len=%u",
                  _name.c_str(),
                  r,
                  pbuf->len);
    }

    log_trace("TCP [%d]%s: Wrote %zd bytes", fd, _name.c_str(), r);

    return r;
}

Endpoint::AcceptState TcpEndpoint::accept_msg(const struct buffer *pbuf) const
{
    // reject when TCP endpoint is not connected (but trying to re-connect)
    if (this->fd == -1) {
        return Endpoint::AcceptState::Rejected;
    }

    // otherwise: refer to standard accept rules
    return Endpoint::accept_msg(pbuf);
}

void TcpEndpoint::close()
{
    if (fd > -1) {
        Mainloop::get_instance().remove_fd(fd);
        ::close(fd);

        log_info("TCP [%d]%s: Connection closed", fd, _name.c_str());
    }

    fd = -1;
}

bool TcpEndpoint::validate_config(const TcpEndpointConfig &config)
{
    if (config.address.empty()) {
        log_error("TcpEndpoint %s: IP address must be specified", config.name.c_str());
        return false;
    }

    if (!validate_ip(config.address)) {
        log_error("TcpEndpoint %s: Invalid IP address %s",
                  config.name.c_str(),
                  config.address.c_str());
        return false;
    }

    if (config.port == 0 || config.port == ULONG_MAX) {
        log_error("TcpEndpoint %s: Invalid or unset TCP port %lu",
                  config.name.c_str(),
                  config.port);
        return false;
    }

    return true;
}

void TcpEndpoint::_schedule_reconnect()
{
    Timeout *t;
    if (_retry_timeout <= 0) {
        return;
    }

    this->close();

    t = Mainloop::get_instance().add_timeout(
        MSEC_PER_SEC * _retry_timeout,
        std::bind(&TcpEndpoint::_retry_timeout_cb, this, std::placeholders::_1),
        this);

    if (t == nullptr) {
        log_warning("Could not create retry timeout for TCP endpoint %s:%lu\n"
                    "No attempts to reconnect will be made",
                    _ip.c_str(),
                    _port);
    }
}

bool TcpEndpoint::_retry_timeout_cb(void *data)
{
    auto *tcp = (TcpEndpoint *)data;

    if (!tcp->reopen()) {
        return true; // try again
    }

    Mainloop::get_instance().add_fd(fd, tcp, EPOLLIN);

    return false; // connection is fine now, no retry
}
