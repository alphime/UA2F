#include "handler.h"
#include <arpa/inet.h>
#include "cache.h"
#include "custom.h"
#include "statistics.h"
#include "util.h"

#ifdef UA2F_ENABLE_UCI
#include "config.h"
#endif

#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv6.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/pktbuff.h>

#define MAX_USER_AGENT_LENGTH (0xffff + (MNL_SOCKET_BUFFER_SIZE / 2))
static char *replacement_user_agent_string = NULL;

static int replacement_user_agent_replace_len = -1;
static unsigned int replacement_user_agent_blank_record = 0;

#define USER_AGENT_MATCH "\r\nUser-Agent:"
#define USER_AGENT_MATCH_LENGTH 13

#define CONNMARK_ESTIMATE_LOWER 16
#define CONNMARK_ESTIMATE_UPPER 32
#define CONNMARK_ESTIMATE_VERDICT 33

#define CONNMARK_NOT_HTTP 43
#define CONNMARK_HTTP 44

bool use_conntrack = true;
static bool cache_initialized = false;

void init_handler() {
    replacement_user_agent_string = malloc(MAX_USER_AGENT_LENGTH);

    bool ua_set = false;

#ifdef UA2F_ENABLE_UCI
    if (config.use_custom_ua) {
        memset(replacement_user_agent_string, ' ', MAX_USER_AGENT_LENGTH);
        strncpy(replacement_user_agent_string, config.custom_ua, strlen(config.custom_ua));
        syslog(LOG_INFO, "Using config user agent string: %s", replacement_user_agent_string);
        ua_set = true;
    }

    if (config.disable_connmark) {
        use_conntrack = false;
        syslog(LOG_INFO, "Conntrack cache disabled by config.");
    }
#endif

#ifdef UA2F_CUSTOM_UA
    if (!ua_set) {
        memset(replacement_user_agent_string, ' ', MAX_USER_AGENT_LENGTH);
        strncpy(replacement_user_agent_string, UA2F_CUSTOM_UA, strlen(UA2F_CUSTOM_UA));
        syslog(LOG_INFO, "Using embed user agent string: %s", replacement_user_agent_string);
        ua_set = true;
    }
#endif

    if (!ua_set) {
        memset(replacement_user_agent_string, 'F', MAX_USER_AGENT_LENGTH);
        syslog(LOG_INFO, "Custom user agent string not set, using default F-string.");
    }

    syslog(LOG_INFO, "Handler initialized.");
}

struct mark_op {
    bool should_set;
    uint32_t mark;
};

static void send_verdict(const struct nf_queue *queue, const struct nf_packet *pkt, const struct mark_op mark,
                         struct pkt_buff *mangled_pkt_buff) {
    struct nlmsghdr *nlh = nfqueue_put_header(pkt->queue_num, NFQNL_MSG_VERDICT);
    if (nlh == NULL) {
        syslog(LOG_ERR, "failed to put nfqueue header");
        goto end;
    }
    nfq_nlmsg_verdict_put(nlh, pkt->packet_id, NF_ACCEPT);

    if (mark.should_set) {
        struct nlattr *nest = mnl_attr_nest_start_check(nlh, SEND_BUF_LEN, NFQA_CT);
        if (nest == NULL) {
            syslog(LOG_ERR, "failed to put nfqueue attr");
            goto end;
        }
        if (!mnl_attr_put_u32_check(nlh, SEND_BUF_LEN, CTA_MARK, htonl(mark.mark))) {
            syslog(LOG_ERR, "failed to put nfqueue attr");
            goto end;
        }
        mnl_attr_nest_end(nlh, nest);
    }

    if (mangled_pkt_buff != NULL) {
        nfq_nlmsg_verdict_put_pkt(nlh, pktb_data(mangled_pkt_buff), pktb_len(mangled_pkt_buff));
    }

    const __auto_type ret = mnl_socket_sendto(queue->nl_socket, nlh, nlh->nlmsg_len);
    if (ret == -1) {
        syslog(LOG_ERR, "failed to send verdict: %s", strerror(errno));
    }

end:
    if (nlh != NULL) {
        free(nlh);
    }
}

static void add_to_cache(const struct nf_packet *pkt) {
    struct addr_port target = {
        .addr = pkt->orig.dst,
        .port = pkt->orig.dst_port,
    };

    cache_add(target);
}

static struct mark_op get_next_mark(const struct nf_packet *pkt, const bool has_ua) {
    if (!use_conntrack) {
        return (struct mark_op){false, 0};
    }

    // I didn't think this will happen, but just in case
    // firewall should already have a rule to return all marked with CONNMARK_NOT_HTTP packets
    if (pkt->conn_mark == CONNMARK_NOT_HTTP) {
        syslog(LOG_WARNING, "Packet has already been marked as not http. Maybe firewall rules are wrong?");
        return (struct mark_op){false, 0};
    }

    if (pkt->conn_mark == CONNMARK_HTTP) {
        return (struct mark_op){false, 0};
    }

    if (has_ua) {
        return (struct mark_op){true, CONNMARK_HTTP};
    }

    if (!pkt->has_connmark || pkt->conn_mark == 0) {
        return (struct mark_op){true, CONNMARK_ESTIMATE_LOWER};
    }

    if (pkt->conn_mark == CONNMARK_ESTIMATE_VERDICT) {
        add_to_cache(pkt);
        return (struct mark_op){true, CONNMARK_NOT_HTTP};
    }

    if (pkt->conn_mark >= CONNMARK_ESTIMATE_LOWER && pkt->conn_mark <= CONNMARK_ESTIMATE_UPPER) {
        return (struct mark_op){true, pkt->conn_mark + 1};
    }

    syslog(LOG_WARNING, "Unexpected connmark value: %d, Maybe other program has changed connmark?", pkt->conn_mark);
    return (struct mark_op){true, pkt->conn_mark + 1};
}

bool should_ignore(const struct nf_packet *pkt) {
    bool retval = false;
    struct addr_port target = {
        .addr = pkt->orig.dst,
        .port = pkt->orig.dst_port,
    };

    retval = cache_contains(target);

    return retval;
}

/*
    当replacement_user_agent_string出现` ...`时，代表开启UA后缀补充功能
    比如replacement_user_agent_string形参为`Mozilla/5.0 (Linux; Android 14; x64) ...`
    ua_start为`Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0`
    replacement_user_agent_string最终结果为`Mozilla/5.0 (Linux; Android 14; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0`
    ，且返回为true；
    当空格不够且没有括号，会保留原始UA 返回false，为什么这么做呢？因为提升大部分应用兼容性
    ? syslog会出现空指针异常？？？
*/
bool append_origin_UA(char *ua_start, unsigned int ua_len, char *result_ua_string) {
    char *ua_copy = replacement_user_agent_string;
    char assign_last_char = 0;
    if (ua_len <= 0)
        return false;
    strncpy(result_ua_string, replacement_user_agent_string, (ua_len > replacement_user_agent_replace_len ? replacement_user_agent_replace_len : ua_len));
    // replacement_user_agent_replace_len: -1 未处理； -2 不开启UA后缀补充； >0 开启UA后缀补充，值为replacement_user_agent_string长度（不包含`...`）。
    if (replacement_user_agent_replace_len == -1) {
        replacement_user_agent_replace_len = 0;
        bool find_append_symbol = false;        // 找到UA后缀补充标识符
        while (*ua_copy != 0)
        {
            char c = *ua_copy;
            if (c == ' ') {
                if (assign_last_char != '(')
                    replacement_user_agent_blank_record++;      // 记录UA空格
                // 当出现` ...`时，开启UA后缀补充
                if (*(ua_copy + 1) == '.' && *(ua_copy + 2) == '.' && *(ua_copy + 3) == '.') {
                    replacement_user_agent_replace_len++;
                    find_append_symbol = true;
                    break;
                }
            }
            else if (c == '(' || c == ')') {
                assign_last_char = c;
            }
            
            ua_copy++;
            replacement_user_agent_replace_len++;       // 计算replacement_user_agent_string长度（不包含`...`）
        }
        if (!find_append_symbol)
            replacement_user_agent_replace_len = -2;
    }

    if (replacement_user_agent_replace_len <= 0) {
        return true;
    }
    
    // 后续代码是拼接 replacement_user_agent_string + ua_start的第replacement_user_agent_blank_record空格之后的内容并存到replacement_user_agent_string
    
    ua_copy = ua_start;
    assign_last_char = 0;       // 在这里 assign_last_char 一旦检测到'('，将会暂停记录上一次的字符，直到检测到')'
    bool has_find_bracket = false;
    int copy_part_ua_len = 0;      // 复制后面部分的ua长度（值有可能小于0！）
    for (int i = 0, s_blank = 0; i < ua_len; i++)
    {
        if (s_blank == replacement_user_agent_blank_record) {
            // replacement_user_agent_replace_len + copy_part_ua_len < fix_ua_len
            copy_part_ua_len = ua_len - ((replacement_user_agent_replace_len < i) ? i : replacement_user_agent_replace_len);
            break;
        }

        if (*ua_copy == '(' || *ua_copy == ')') {
            if (assign_last_char != *ua_copy)
                has_find_bracket = true;
            assign_last_char = *ua_copy;
        }

        else {
            if (*ua_copy == ' ' && assign_last_char != '(' && assign_last_char != ' ') {
                s_blank++;
            }

            if (assign_last_char != '(')
                assign_last_char = *ua_copy;
        }

        ua_copy++;
    }

    if (copy_part_ua_len > 0) {
        strncpy(result_ua_string + replacement_user_agent_replace_len, ua_copy, copy_part_ua_len);
        const int offset_fill_blank = copy_part_ua_len + replacement_user_agent_replace_len;
        if (offset_fill_blank < ua_len)
            memset(result_ua_string + offset_fill_blank, ' ', ua_len - offset_fill_blank);
        return true;
    }
    
    if (has_find_bracket) {
        // 补齐空格，如结果为`Mozilla/5.0 (Linux; Android 14; x64) `
        if (ua_len > replacement_user_agent_replace_len)
            memset(result_ua_string + replacement_user_agent_replace_len, ' ', ua_len - replacement_user_agent_replace_len);
        return true;
    }
    return false;
}

void handle_packet(const struct nf_queue *queue, const struct nf_packet *pkt) {
    if (use_conntrack) {
        if (!pkt->has_conntrack) {
            use_conntrack = false;
            syslog(LOG_WARNING, "Packet has no conntrack. Switching to no cache mode.");
            syslog(LOG_WARNING, "Note that this may lead to performance degradation. Especially on low-end routers.");
        } else {
            if (!cache_initialized) {
                init_not_http_cache(60);
                cache_initialized = true;
            }
        }
    }

    if (use_conntrack && should_ignore(pkt)) {
        send_verdict(queue, pkt, (struct mark_op){true, CONNMARK_NOT_HTTP}, NULL);
        goto end;
    }

    struct pkt_buff *pkt_buff = pktb_alloc(AF_INET, pkt->payload, pkt->payload_len, 0);
    ASSERT(pkt_buff != NULL);

    int type;

    if (use_conntrack) {
        type = pkt->orig.ip_version;
    } else {
        const __auto_type ip_hdr = nfq_ip_get_hdr(pkt_buff);
        if (ip_hdr == NULL) {
            type = IPV6;
        } else {
            type = IPV4;
        }
    }

    if (type == IPV4) {
        count_ipv4_packet();
    } else {
        count_ipv6_packet();
    }

    if (type == IPV4) {
        const __auto_type ip_hdr = nfq_ip_get_hdr(pkt_buff);
        if (nfq_ip_set_transport_header(pkt_buff, ip_hdr) < 0) {
            syslog(LOG_ERR, "Failed to set ipv4 transport header");
            goto end;
        }
    } else {
        const __auto_type ip_hdr = nfq_ip6_get_hdr(pkt_buff);
        if (nfq_ip6_set_transport_header(pkt_buff, ip_hdr, IPPROTO_TCP) < 0) {
            syslog(LOG_ERR, "Failed to set ipv6 transport header");
            goto end;
        }
    }

    const __auto_type tcp_hdr = nfq_tcp_get_hdr(pkt_buff);
    if (tcp_hdr == NULL) {
        // This packet is not tcp, pass it
        send_verdict(queue, pkt, (struct mark_op){false, 0}, NULL);
        syslog(LOG_WARNING, "Received non-tcp packet. You may set wrong firewall rules.");
        goto end;
    }

    const __auto_type tcp_payload = nfq_tcp_get_payload(tcp_hdr, pkt_buff);
    const __auto_type tcp_payload_len = nfq_tcp_get_payload_len(tcp_hdr, pkt_buff);

    if (tcp_payload == NULL || tcp_payload_len < USER_AGENT_MATCH_LENGTH) {
        send_verdict(queue, pkt, get_next_mark(pkt, false), NULL);
        goto end;
    }

    count_tcp_packet();

    // cannot find User-Agent: in this packet
    if (tcp_payload_len - 2 < USER_AGENT_MATCH_LENGTH) {
        send_verdict(queue, pkt, get_next_mark(pkt, false), NULL);
        goto end;
    }

    // FIXME: can lead to false positive,
    //        should also get CTA_COUNTERS_ORIG to check if this packet is a initial tcp packet

    //    if (!is_http_protocol(tcp_payload, tcp_payload_len)) {
    //        send_verdict(queue, pkt, get_next_mark(pkt, false), NULL);
    //        goto end;
    //    }
    count_http_packet();

    const void *search_start = tcp_payload;
    unsigned int search_length = tcp_payload_len;
    bool has_ua = false;

    while (true) {
        // minimal length of User-Agent: is 12
        if (search_length - 2 < USER_AGENT_MATCH_LENGTH) {
            break;
        }

        char *ua_pos = memncasemem(search_start, search_length, USER_AGENT_MATCH, USER_AGENT_MATCH_LENGTH);
        if (ua_pos == NULL) {
            break;
        }

        has_ua = true;

        void *ua_start = ua_pos + USER_AGENT_MATCH_LENGTH;

        // for non-standard user-agent like User-Agent:XXX with no space after colon
        if (*(char *)ua_start == ' ') {
            ua_start++;
        }

        const void *ua_end = memchr(ua_start, '\r', tcp_payload_len - (ua_start - tcp_payload));
        if (ua_end == NULL) {
            syslog(LOG_INFO, "User-Agent header is not terminated with \\r, not mangled.");
            send_verdict(queue, pkt, get_next_mark(pkt, true), NULL);
            goto end;
        }
        const unsigned int ua_len = ua_end - ua_start;
        const unsigned long ua_offset = ua_start - tcp_payload;

        // syslog(LOG_INFO, "Origin UA: %s", ua_start);

        char new_ua_string[ua_len + 1];
        new_ua_string[ua_len] = 0;
        bool needed_replace =  append_origin_UA(ua_start, ua_len, new_ua_string);
        if (needed_replace) {
           // Looks it's impossible to mangle packet failed, so we just drop it
            if (type == IPV4) {
                nfq_tcp_mangle_ipv4(pkt_buff, ua_offset, ua_len, new_ua_string, ua_len);
            } else {
                nfq_tcp_mangle_ipv6(pkt_buff, ua_offset, ua_len, new_ua_string, ua_len);
            }
        } else {
            // strncpy(new_ua_string, ua_start, ua_len);
            // syslog(LOG_INFO, "Using disposed origin UA: %s", new_ua_string);
            if (ua_len <= 0)
                syslog(LOG_INFO, "Origin UA empty!");
        }

        search_length = tcp_payload_len - (ua_end - tcp_payload);
        search_start = ua_end;
    }

    if (has_ua) {
        count_user_agent_packet();
    }

    send_verdict(queue, pkt, get_next_mark(pkt, has_ua), pkt_buff);

end:
    free(pkt->payload);
    if (pkt_buff != NULL) {
        pktb_free(pkt_buff);
    }

    try_print_statistics();
}

#undef MAX_USER_AGENT_LENGTH
#undef USER_AGENT_MATCH_LENGTH

#undef CONNMARK_ESTIMATE_LOWER
#undef CONNMARK_ESTIMATE_UPPER
#undef CONNMARK_ESTIMATE_VERDICT

#undef CONNMARK_NOT_HTTP
#undef CONNMARK_HTTP
