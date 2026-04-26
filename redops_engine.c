#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#define MAX_LINE   4096
#define MAX_TOKENS 64
#define MAX_FINDS  2048
#define IP_LEN     40
#define PORT_LEN   8
#define STR_LEN    256
#define BIG_STR    1024


typedef struct {
    char ip[IP_LEN];
    char port[PORT_LEN];
    char protocol[16];
    char service[STR_LEN];
    char version[STR_LEN];
    char state[16];
    char os_guess[STR_LEN];
    int  confidence;
} HostFinding;

typedef struct {
    char type[32];
    char host[IP_LEN];
    char detail[BIG_STR];
    int  severity;
} VulnFinding;

typedef struct {
    char credential[STR_LEN];
    char host[IP_LEN];
    char protocol[32];
    char source[STR_LEN];
} CredFinding;

typedef struct {
    HostFinding  hosts[MAX_FINDS];
    VulnFinding  vulns[MAX_FINDS];
    CredFinding  creds[MAX_FINDS];
    int          host_count;
    int          vuln_count;
    int          cred_count;
    int          lines_processed;
    int          parse_errors;
} ParseResult;


static void str_lower(char *s) {
    for (; *s; s++) *s = (char)tolower((unsigned char)*s);
}

static char *str_trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s) - 1;
    while (e > s && isspace((unsigned char)*e)) *e-- = '\0';
    return s;
}

static int starts_with(const char *s, const char *prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

static int contains(const char *haystack, const char *needle) {
    return strstr(haystack, needle) != NULL;
}

static int extract_ip(const char *line, char *out) {
    const char *p = line;
    while (*p) {
        int a, b, c, d, n = 0;
        if (sscanf(p, "%d.%d.%d.%d%n", &a, &b, &c, &d, &n) == 4
            && a >= 0 && a <= 255 && b >= 0 && b <= 255
            && c >= 0 && c <= 255 && d >= 0 && d <= 255
            && (p[n] == '\0' || !isdigit((unsigned char)p[n]))) {
            snprintf(out, IP_LEN, "%d.%d.%d.%d", a, b, c, d);
            return 1;
        }
        p++;
    }
    return 0;
}

static int extract_port(const char *line, char *out) {
    const char *p = line;
    while (*p) {
        int port, n = 0;
        if (sscanf(p, "%d%n", &port, &n) == 1
            && port > 0 && port <= 65535
            && (p[n] == '/' || p[n] == ' ' || p[n] == '\t')) {
            snprintf(out, PORT_LEN, "%d", port);
            return 1;
        }
        p++;
    }
    return 0;
}


static int parse_nmap_line(const char *raw, ParseResult *res) {
    if (res->host_count >= MAX_FINDS) return 0;
    char line[MAX_LINE];
    strncpy(line, raw, MAX_LINE-1);
    str_lower(line);

    if (starts_with(line, "host:")) {
        HostFinding *h = &res->hosts[res->host_count];
        memset(h, 0, sizeof(*h));
        if (extract_ip(line + 5, h->ip)) {
            strncpy(h->state, "up", sizeof(h->state)-1);
            h->confidence = 90;
            res->host_count++;
            return 1;
        }
    }

    if (starts_with(line, "ports:")) {
        char *tok = strtok(line + 6, ",\t\n");
        while (tok) {
            tok = str_trim(tok);
            HostFinding *h = &res->hosts[res->host_count];
            memset(h, 0, sizeof(*h));
            int port; char state[16], proto[16], svc[64], ver[128];
            memset(state,0,sizeof(state)); memset(proto,0,sizeof(proto));
            memset(svc,0,sizeof(svc));     memset(ver,0,sizeof(ver));
            if (sscanf(tok, "%d/%15[^/]/%15[^/]//%63[^/]//%127[^/]",
                       &port, state, proto, svc, ver) >= 3) {
                snprintf(h->port, PORT_LEN, "%d", port);
                strncpy(h->state,    state, sizeof(h->state)-1);
                strncpy(h->protocol, proto, sizeof(h->protocol)-1);
                strncpy(h->service,  svc,   sizeof(h->service)-1);
                strncpy(h->version,  ver,   sizeof(h->version)-1);
                h->confidence = 95;
                res->host_count++;
            }
            tok = strtok(NULL, ",\t\n");
        }
        return 1;
    }

    {
        int port, n = 0;
        char proto[16], state[16], svc[64], ver[128];
        memset(proto,0,sizeof(proto)); memset(state,0,sizeof(state));
        memset(svc,0,sizeof(svc));     memset(ver,0,sizeof(ver));
        if (sscanf(line, "%d/%15[^ \t]%n", &port, proto, &n) == 2) {
            const char *rest = str_trim((char*)line + n);
            if (sscanf(rest, "%15s %63s %127[^\n]", state, svc, ver) >= 2) {
                if (strcmp(state,"open")==0 || strcmp(state,"filtered")==0) {
                    HostFinding *h = &res->hosts[res->host_count];
                    memset(h, 0, sizeof(*h));
                    snprintf(h->port, PORT_LEN, "%d", port);
                    strncpy(h->protocol, proto, sizeof(h->protocol)-1);
                    strncpy(h->state,    state, sizeof(h->state)-1);
                    strncpy(h->service,  svc,   sizeof(h->service)-1);
                    strncpy(h->version,  ver,   sizeof(h->version)-1);
                    h->confidence = 90;
                    res->host_count++;
                    return 1;
                }
            }
        }
    }
    return 0;
}


static int parse_cme_line(const char *raw, ParseResult *res) {
    char line[MAX_LINE];
    strncpy(line, raw, MAX_LINE-1);

    char proto[16], ip[IP_LEN], port[PORT_LEN], host[64], tag[16], rest[BIG_STR];
    memset(proto,0,sizeof(proto)); memset(ip,0,sizeof(ip));
    memset(port,0,sizeof(port));   memset(host,0,sizeof(host));
    memset(tag,0,sizeof(tag));     memset(rest,0,sizeof(rest));

    if (sscanf(line, "%15s %39s %7s %63s %15s %1023[^\n]",
               proto, ip, port, host, tag, rest) >= 5) {

        if (strcmp(tag, "[+]") == 0 && res->cred_count < MAX_FINDS) {
            CredFinding *c = &res->creds[res->cred_count];
            memset(c, 0, sizeof(*c));
            strncpy(c->host,     ip,    sizeof(c->host)-1);
            strncpy(c->protocol, proto, sizeof(c->protocol)-1);
            strncpy(c->source,   host,  sizeof(c->source)-1);
            char *cr = str_trim(rest);
            snprintf(c->credential, sizeof(c->credential)-1, "%s", cr);
            res->cred_count++;

            if (contains(rest, "(Pwn3d!)") && res->vuln_count < MAX_FINDS) {
                VulnFinding *v = &res->vulns[res->vuln_count];
                memset(v, 0, sizeof(*v));
                strncpy(v->type,   "local_admin", sizeof(v->type)-1);
                strncpy(v->host,   ip,            sizeof(v->host)-1);
                snprintf(v->detail, sizeof(v->detail)-1,
                         "%s local admin via %s (host: %s)", cr, proto, host);
                v->severity = 4;
                res->vuln_count++;
            }
            return 1;
        }

        if (contains(line, "signing:False") || contains(line, "signing: False")) {
            if (res->vuln_count < MAX_FINDS) {
                VulnFinding *v = &res->vulns[res->vuln_count];
                memset(v, 0, sizeof(*v));
                strncpy(v->type, "smb_signing_disabled", sizeof(v->type)-1);
                strncpy(v->host, ip, sizeof(v->host)-1);
                snprintf(v->detail, sizeof(v->detail)-1,
                         "SMB signing not required on %s (%s)", host, ip);
                v->severity = 3;
                res->vuln_count++;
                return 1;
            }
        }
    }
    return 0;
}


static int parse_cred_line(const char *raw, ParseResult *res) {
    if (res->cred_count >= MAX_FINDS) return 0;
    char line[MAX_LINE];
    strncpy(line, raw, MAX_LINE-1);
    char *p = str_trim(line);

    char user[64], rid[16], lm[64], nt[64];
    if (sscanf(p, "%63[^:]:%15[^:]:%63[^:]:%63[^: \t\n]", user, rid, lm, nt) == 4
        && strlen(nt) == 32) {
        CredFinding *c = &res->creds[res->cred_count];
        memset(c, 0, sizeof(*c));
        snprintf(c->credential, sizeof(c->credential)-1, "%s:%s", user, nt);
        strncpy(c->protocol, "sam_dump", sizeof(c->protocol)-1);
        strncpy(c->source,   "hash",    sizeof(c->source)-1);
        res->cred_count++;
        return 1;
    }

    return 0;
}


void parse_tool_output(const char *text, size_t len,
                       ParseResult *res, int tool_hint) {
    char line[MAX_LINE];
    size_t i = 0, j = 0;

    while (i <= len) {
        char ch = (i < len) ? text[i] : '\n';
        if (ch == '\n' || ch == '\r' || i == len) {
            if (j > 0) {
                line[j] = '\0';
                char *trimmed = str_trim(line);
                if (*trimmed && trimmed[0] != '#') {
                    int hint = tool_hint;
                    if (hint == 0) {
                        char lo[MAX_LINE];
                        strncpy(lo, trimmed, MAX_LINE-1);
                        str_lower(lo);
                        if (contains(lo, "nmap") || contains(lo, "/tcp") || contains(lo, "/udp"))
                            hint = 1;
                        else if (contains(lo, "smb") && contains(lo, "445"))
                            hint = 2;
                        else if (contains(lo, "administrator") || contains(lo, "ntlm"))
                            hint = 3;
                    }
                    switch(hint) {
                        case 1: parse_nmap_line(trimmed, res); break;
                        case 2: parse_cme_line(trimmed, res); break;
                        case 3: parse_cred_line(trimmed, res); break;
                        default:
                            parse_nmap_line(trimmed, res) ||
                            parse_cme_line(trimmed, res)  ||
                            parse_cred_line(trimmed, res);
                    }
                }
                res->lines_processed++;
            }
            j = 0;
        } else if (j < MAX_LINE - 1) {
            line[j++] = ch;
        }
        i++;
    }
}


size_t serialize_result(const ParseResult *res, char *out, size_t out_size) {
    size_t pos = 0;

#define W(...) do { int _n = snprintf(out+pos, out_size-pos, __VA_ARGS__); \
                    if (_n > 0) pos += (size_t)_n; } while(0)

    W("{\"hosts\":[");
    for (int i = 0; i < res->host_count; i++) {
        const HostFinding *h = &res->hosts[i];
        if (i) W(",");
        W("{\"ip\":\"%s\",\"port\":\"%s\",\"proto\":\"%s\","
          "\"service\":\"%s\",\"version\":\"%s\","
          "\"state\":\"%s\",\"os\":\"%s\",\"conf\":%d}",
          h->ip, h->port, h->protocol,
          h->service, h->version,
          h->state, h->os_guess, h->confidence);
    }
    W("],\"vulns\":[");
    for (int i = 0; i < res->vuln_count; i++) {
        const VulnFinding *v = &res->vulns[i];
        if (i) W(",");
        char esc[BIG_STR*2]; size_t ei=0;
        for (const char *d=v->detail; *d && ei<sizeof(esc)-2; d++) {
            if (*d=='"' || *d=='\\') esc[ei++]='\\';
            esc[ei++] = *d;
        }
        esc[ei]='\0';
        W("{\"type\":\"%s\",\"host\":\"%s\",\"detail\":\"%s\",\"sev\":%d}",
          v->type, v->host, esc, v->severity);
    }
    W("],\"creds\":[");
    for (int i = 0; i < res->cred_count; i++) {
        const CredFinding *c = &res->creds[i];
        if (i) W(",");
        char esc[STR_LEN*2]; size_t ei=0;
        for (const char *d=c->credential; *d && ei<sizeof(esc)-2; d++) {
            if (*d=='"' || *d=='\\') esc[ei++]='\\';
            esc[ei++] = *d;
        }
        esc[ei]='\0';
        W("{\"cred\":\"%s\",\"host\":\"%s\",\"proto\":\"%s\",\"src\":\"%s\"}",
          esc, c->host, c->protocol, c->source);
    }
    W("],\"meta\":{\"lines\":%d,\"errors\":%d}}",
      res->lines_processed, res->parse_errors);

    return pos;
#undef W
}


size_t parse_and_serialize(const char *text, size_t text_len,
                           char *json_out, size_t json_size,
                           int tool_hint) {
    ParseResult res;
    memset(&res, 0, sizeof(res));
    parse_tool_output(text, text_len, &res, tool_hint);
    return serialize_result(&res, json_out, json_size);
}


void quick_stats(const char *text, size_t len, char *out, int tool_hint) {
    ParseResult res;
    memset(&res, 0, sizeof(res));
    parse_tool_output(text, len, &res, tool_hint);
    snprintf(out, 64, "%d,%d,%d,%d",
             res.host_count, res.vuln_count, res.cred_count, res.lines_processed);
}
