"""
IoC Investigation HTML Report Generator
=======================================
Self-contained HTML report generator for Indicator-of-Compromise investigations.
Zero external dependencies — Python 3 stdlib only.

Usage:
    python3 generate_html_report.py <json_file> [--output-dir DIR]

Reads a JSON file matching the ioc-investigation export structure
(investigation_metadata, threat_intelligence, ip_enrichment, activity_analysis,
alert_correlation, cve_correlation, organizational_exposure, risk_assessment)
and generates a styled dark-theme HTML report. One report per IoC.

Design mirrors incident-investigation/generate_html_report.py (same CSS,
CONFIDENTIAL watermark, two-column layout) for visual consistency across the suite.
"""

import json
import sys
import os
import re
import socket
from datetime import datetime, timezone
from html import escape


# ═══════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════

def get_user():
    try:
        return os.getlogin().upper()
    except Exception:
        return os.environ.get('USERNAME', 'AGENT').upper()


def get_host():
    try:
        return socket.gethostname().upper()
    except Exception:
        return 'UNKNOWN'


def esc(v):
    return escape(str(v)) if v not in (None, '') else ''


def defang_ip(ip):
    """Defang an IP address: 1.2.3.4 -> 1[.]2[.]3[.]4"""
    if not ip:
        return ''
    return re.sub(r'\.', '[.]', str(ip))


def defang_url(url):
    """Defang a URL/domain: https://evil.com -> hxxps://evil[.]com"""
    if not url:
        return ''
    s = str(url)
    s = re.sub(r'^https://', 'hxxps://', s)
    s = re.sub(r'^http://', 'hxxp://', s)
    s = re.sub(r'\.', '[.]', s)
    return s


def defang_ioc(value, ioc_type):
    t = (ioc_type or '').lower()
    if t in ('ip', 'ipv4', 'ipv6'):
        return defang_ip(value)
    if t in ('domain', 'url', 'dns'):
        return defang_url(value)
    return esc(value)


def severity_color(sev):
    s = (sev or '').lower()
    return {
        'critical': '#d13438', 'high': '#f65314', 'medium': '#ffbb00',
        'low': '#7cbb00', 'informational': '#00a1f1', 'none': '#7cbb00',
    }.get(s, '#737373')


def verdict_color(verdict):
    v = (verdict or '').lower()
    return {
        'malicious': '#d13438', 'suspicious': '#f65314',
        'clean': '#7cbb00', 'unknown': '#737373',
    }.get(v, '#737373')


def sev_badge(sev):
    c = severity_color(sev)
    tc = '#1a1a1a' if (sev or '').lower() in ('medium', 'low') else 'white'
    return (f'<span style="background:{c};color:{tc};padding:2px 9px;border-radius:3px;'
            f'font-size:0.85em;font-weight:600;">{esc(sev)}</span>')


def pill(text, bg='#555', tc='white'):
    return (f'<span style="background:{bg};color:{tc};padding:2px 8px;border-radius:12px;'
            f'font-size:0.8em;margin:2px;display:inline-block;">{esc(text)}</span>')


def fmt_ts(ts):
    if not ts:
        return '—'
    s = str(ts)
    if 'T' in s:
        return s[:19].replace('T', ' ')
    return s[:19]


def as_list(v):
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


# ═══════════════════════════════════════════════════════════════════
# HTML REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════

class IoCReportGenerator:
    def __init__(self, data):
        self.data = data
        self.meta = data.get('investigation_metadata', {})
        self.ti = data.get('threat_intelligence', {})
        self.enrich = data.get('ip_enrichment', {})
        self.activity = data.get('activity_analysis', {})
        self.alerts = data.get('alert_correlation', {})
        self.cve = data.get('cve_correlation', {})
        self.exposure = data.get('organizational_exposure', {})
        self.risk = data.get('risk_assessment', {})
        self.ioc_type = self.meta.get('ioc_type', 'ioc')
        self.ioc_value = self.meta.get('ioc_value', 'unknown')

    # ─── IoC Metadata Card ────────────────────────────────────────
    def _metadata_card(self):
        m = self.meta
        fields = [
            ('IoC Type', (self.ioc_type or '').upper()),
            ('IoC Value', defang_ioc(self.ioc_value, self.ioc_type)),
            ('Original Input', esc(m.get('ioc_original'))),
            ('Investigated', fmt_ts(m.get('investigation_timestamp'))),
            ('Range Start', fmt_ts(m.get('date_range_start'))),
            ('Range End', fmt_ts(m.get('date_range_end'))),
            ('Elapsed', f"{m.get('elapsed_time_seconds')}s" if m.get('elapsed_time_seconds') else None),
        ]
        rows = ''
        for label, val in fields:
            if not val:
                continue
            mono = ' style="font-family:monospace;"' if label == 'IoC Value' else ''
            rows += f'<tr><td class="l">{label}</td><td{mono}>{val}</td></tr>'
        return (f'<div class="section"><h2>🔍 IoC Metadata</h2>'
                f'<table style="font-size:0.92em;"><tbody>{rows}</tbody></table></div>')

    # ─── Verdict / Risk Card ──────────────────────────────────────
    def _verdict_card(self):
        verdict = self.ti.get('verdict', 'Unknown')
        conf = self.ti.get('confidence_score', 0)
        overall = self.risk.get('overall_risk', '')
        r_conf = self.risk.get('confidence', '')
        vc = verdict_color(verdict)
        rc = severity_color(overall)
        overall_html = ''
        if overall:
            overall_html = (f'<div style="margin-top:10px;text-align:center;">'
                            f'<span style="font-size:1.4em;font-weight:bold;color:{rc};">{esc(overall)}</span>'
                            f'<div class="l">Overall Risk'
                            f'{f" · {esc(r_conf)} confidence" if r_conf else ""}</div></div>')
        return (f'<div class="section"><h2>⚖️ Verdict</h2>'
                f'<div style="text-align:center;margin:6px 0;">'
                f'<span style="font-size:1.8em;font-weight:bold;color:{vc};">{esc(verdict)}</span>'
                f'<div class="l">TI confidence: {esc(conf)}</div></div>'
                f'{overall_html}</div>')

    # ─── Key Metrics ──────────────────────────────────────────────
    def _metrics(self):
        n_ti = len(as_list(self.ti.get('sentinel_ti_matches'))) + len(as_list(self.ti.get('defender_ioc_matches')))
        n_alerts = self.alerts.get('total_alerts', 0) or 0
        n_dev = self.exposure.get('total_affected_devices', 0) or self.cve.get('total_unique_affected_devices', 0) or 0
        n_cve = len(as_list(self.cve.get('cve_ids_found')))

        def mc(v, l, c='#00a1f1'):
            return (f'<div class="metric" style="background:linear-gradient(135deg,{c},{c}cc);">'
                    f'<div class="mv">{v}</div><div class="ml">{l}</div></div>')

        vc = verdict_color(self.ti.get('verdict'))
        return (f'<div class="section"><h2>📊 Key Metrics</h2><div class="metrics">'
                f'{mc(n_ti, "TI Matches", vc)}{mc(n_alerts, "Alerts", "#f65314")}'
                f'{mc(n_dev, "Affected Devices", "#9b59b6")}{mc(n_cve, "CVEs", "#ff7f00")}'
                f'</div></div>')

    # ─── Threat Intelligence ──────────────────────────────────────
    def _threat_intel(self):
        families = as_list(self.ti.get('threat_families'))
        sti = as_list(self.ti.get('sentinel_ti_matches'))
        dioc = as_list(self.ti.get('defender_ioc_matches'))
        dalerts = as_list(self.ti.get('defender_alerts'))
        if not (families or sti or dioc or dalerts):
            return ('<div class="section"><h2>🧠 Threat Intelligence</h2>'
                    '<p style="color:#7cbb00;">✅ No threat-intel matches</p></div>')
        parts = []
        if families:
            parts.append('<div style="margin-bottom:8px;"><span class="l">Threat families:</span> '
                         + ' '.join(pill(f, '#8e44ad') for f in families) + '</div>')

        def _match_rows(items):
            rows = ''
            for it in items[:15]:
                if isinstance(it, str):
                    rows += f'<tr><td style="font-family:monospace;font-size:0.82em;" colspan="3">{esc(it)}</td></tr>'
                    continue
                src = it.get('source') or it.get('SourceSystem') or it.get('provider') or '—'
                desc = it.get('description') or it.get('Description') or it.get('title') or ''
                conf = it.get('confidence') or it.get('Confidence') or ''
                rows += (f'<tr><td style="font-size:0.82em;">{esc(src)}</td>'
                         f'<td style="text-align:center;">{esc(conf)}</td>'
                         f'<td style="font-size:0.82em;">{esc(desc)}</td></tr>')
            return rows

        matches = sti + dioc
        if matches:
            parts.append(
                '<table><thead><tr><th>Source</th><th style="text-align:center;">Confidence</th>'
                f'<th>Detail</th></tr></thead><tbody>{_match_rows(matches)}</tbody></table>')
        if dalerts:
            rows = ''
            for a in dalerts[:12]:
                if isinstance(a, str):
                    rows += f'<tr><td colspan="2" style="font-size:0.82em;">{esc(a)}</td></tr>'
                    continue
                title = a.get('title') or a.get('Title') or a.get('name') or '?'
                sev = a.get('severity') or a.get('Severity') or ''
                rows += f'<tr><td>{esc(title)}</td><td style="text-align:center;">{sev_badge(sev)}</td></tr>'
            parts.append('<div style="margin-top:8px;"><span class="l">Defender alerts:</span>'
                         '<table><tbody>' + rows + '</tbody></table></div>')
        return f'<div class="section"><h2>🧠 Threat Intelligence</h2>{"".join(parts)}</div>'

    # ─── IP Enrichment ────────────────────────────────────────────
    def _ip_enrichment(self):
        e = self.enrich
        if not e:
            return ''
        geo = e.get('geo', {}) or {}
        vpt = e.get('vpn_proxy_tor', {}) or {}
        abuse = e.get('abuseipdb', {}) or {}
        shodan = e.get('shodan', {}) or {}
        has_data = any([geo, vpt, abuse, shodan])
        if not has_data:
            return ''
        parts = []
        # Geo / ISP
        geo_bits = [b for b in [geo.get('city'), geo.get('country'), geo.get('org') or geo.get('isp')] if b]
        if geo_bits:
            parts.append(f'<div><span class="l">Geo / ISP:</span> {esc(" · ".join(str(b) for b in geo_bits))}</div>')
        # VPN/Proxy/Tor flags
        flags = []
        if vpt.get('is_vpn'):
            flags.append(pill('VPN', '#e67e22'))
        if vpt.get('is_proxy'):
            flags.append(pill('Proxy', '#e67e22'))
        if vpt.get('is_tor'):
            flags.append(pill('Tor', '#d13438'))
        if flags:
            parts.append('<div style="margin-top:6px;"><span class="l">Anonymizer:</span> ' + ' '.join(flags) + '</div>')
        # AbuseIPDB
        if abuse:
            score = abuse.get('abuse_confidence_score', 0) or 0
            try:
                score_i = int(score)
            except Exception:
                score_i = 0
            sc = '#d13438' if score_i >= 75 else '#f65314' if score_i >= 25 else '#7cbb00'
            cats = as_list(abuse.get('recent_categories'))
            cats_html = ''
            if cats:
                cats_html = '<div style="margin-top:4px;">' + ' '.join(pill(c, '#555') for c in cats[:6]) + '</div>'
            last = abuse.get('last_reported')
            last_html = f' · last {fmt_ts(last)}' if last else ''
            parts.append(
                '<div style="margin-top:6px;"><span class="l">AbuseIPDB:</span> '
                f'<span style="color:{sc};font-weight:600;">{score_i}/100</span> '
                f'· {esc(abuse.get("total_reports", 0))} reports{last_html}{cats_html}</div>')
        # Shodan
        if shodan:
            ports = as_list(shodan.get('ports'))
            vulns = as_list(shodan.get('vulns'))
            tags = as_list(shodan.get('tags'))
            os_name = shodan.get('os')
            sh_parts = []
            if os_name:
                sh_parts.append(f'<div><span class="l">OS:</span> {esc(os_name)}</div>')
            if ports:
                sh_parts.append('<div style="margin-top:4px;"><span class="l">Ports:</span> '
                                + ' '.join(pill(str(p), '#34495e') for p in ports[:20]) + '</div>')
            if tags:
                tag_html = ' '.join(pill(t, '#d13438' if str(t).lower() == 'c2' else '#8e44ad') for t in tags[:12])
                sh_parts.append(f'<div style="margin-top:4px;"><span class="l">Tags:</span> {tag_html}</div>')
            if vulns:
                sh_parts.append('<div style="margin-top:4px;"><span class="l">CVEs (Shodan):</span> '
                                + ' '.join(pill(str(v), '#c0392b') for v in vulns[:15]) + '</div>')
            if sh_parts:
                parts.append('<div style="margin-top:8px;padding-top:6px;border-top:1px solid #3a3a3a;">'
                             '<span class="l" style="font-weight:600;">Shodan</span>' + ''.join(sh_parts) + '</div>')
        if not parts:
            return ''
        return f'<div class="section"><h2>🌐 IP Enrichment</h2>{"".join(parts)}</div>'

    # ─── Activity Analysis ────────────────────────────────────────
    def _activity(self):
        a = self.activity
        if not a:
            return ''
        parts = []
        net = a.get('network_connections', {}) or {}
        if net and (net.get('total_connections') or net.get('unique_devices')):
            devs = as_list(net.get('top_devices'))
            ports = as_list(net.get('top_ports'))
            procs = as_list(net.get('top_processes'))
            rows = (
                f'<tr><td class="l">Connections</td><td>{esc(net.get("total_connections", 0))}</td></tr>'
                f'<tr><td class="l">Unique devices</td><td>{esc(net.get("unique_devices", 0))}</td></tr>'
                f'<tr><td class="l">Unique users</td><td>{esc(net.get("unique_users", 0))}</td></tr>'
                f'<tr><td class="l">First seen</td><td>{fmt_ts(net.get("first_seen"))}</td></tr>'
                f'<tr><td class="l">Last seen</td><td>{fmt_ts(net.get("last_seen"))}</td></tr>')
            extra = ''
            if devs:
                extra += f'<div style="margin-top:4px;"><span class="l">Top devices:</span> {esc(", ".join(str(d) for d in devs[:8]))}</div>'
            if ports:
                extra += f'<div><span class="l">Top ports:</span> {esc(", ".join(str(p) for p in ports[:12]))}</div>'
            if procs:
                extra += f'<div><span class="l">Top processes:</span> {esc(", ".join(str(p) for p in procs[:8]))}</div>'
            parts.append(f'<div style="margin-bottom:8px;"><span class="l" style="font-weight:600;">🔌 Network</span>'
                         f'<table><tbody>{rows}</tbody></table>{extra}</div>')

        email = a.get('email_delivery', {}) or {}
        if email and email.get('email_count'):
            urls = as_list(email.get('unique_urls'))
            locs = as_list(email.get('delivery_locations'))
            extra = ''
            if urls:
                extra += f'<div><span class="l">URLs:</span> <span style="font-family:monospace;font-size:0.8em;">{esc(", ".join(defang_url(u) for u in urls[:6]))}</span></div>'
            if locs:
                extra += f'<div><span class="l">Locations:</span> {esc(", ".join(str(x) for x in locs[:6]))}</div>'
            parts.append(f'<div style="margin-bottom:8px;"><span class="l" style="font-weight:600;">📧 Email delivery</span>'
                         f'<div>{esc(email.get("email_count"))} emails</div>{extra}</div>')

        fa = a.get('file_activity', {}) or {}
        if fa and (fa.get('event_count') or fa.get('unique_devices')):
            names = as_list(fa.get('file_names'))
            paths = as_list(fa.get('folder_paths'))
            acts = as_list(fa.get('action_types'))
            extra = ''
            if names:
                extra += f'<div><span class="l">Files:</span> {esc(", ".join(str(n) for n in names[:8]))}</div>'
            if paths:
                extra += f'<div><span class="l">Paths:</span> <span style="font-size:0.82em;">{esc(", ".join(str(p) for p in paths[:5]))}</span></div>'
            if acts:
                extra += f'<div><span class="l">Actions:</span> {esc(", ".join(str(x) for x in acts[:8]))}</div>'
            parts.append(f'<div style="margin-bottom:8px;"><span class="l" style="font-weight:600;">📄 File activity</span>'
                         f'<div>{esc(fa.get("event_count", 0))} events · {esc(fa.get("unique_devices", 0))} devices</div>{extra}</div>')

        si = a.get('signin_activity', {}) or {}
        if si and si.get('signin_count'):
            users = as_list(si.get('affected_users'))
            rate = si.get('success_rate', 0)
            extra = f'<div><span class="l">Users:</span> {esc(", ".join(str(u) for u in users[:8]))}</div>' if users else ''
            parts.append(f'<div><span class="l" style="font-weight:600;">🔑 Sign-ins</span>'
                         f'<div>{esc(si.get("signin_count"))} sign-ins · {esc(si.get("unique_users", 0))} users · {esc(rate)}% success</div>{extra}</div>')

        if not parts:
            return ''
        return f'<div class="section"><h2>📈 Activity Analysis</h2>{"".join(parts)}</div>'

    # ─── Alert Correlation ────────────────────────────────────────
    def _alert_correlation(self):
        al = self.alerts
        if not al:
            return ''
        total = al.get('total_alerts', 0) or 0
        sb = al.get('severity_breakdown', {}) or {}
        titles = as_list(al.get('alert_titles'))
        techs = as_list(al.get('attack_techniques'))
        ents = as_list(al.get('affected_entities'))
        if not (total or titles or techs or ents):
            return ''
        chips = ''
        for k in ('high', 'medium', 'low', 'informational'):
            n = sb.get(k, 0) or 0
            if n:
                chips += pill(f'{k.title()}: {n}', severity_color(k),
                              '#1a1a1a' if k in ('medium', 'low') else 'white')
        parts = [f'<div><span class="l">Total alerts:</span> <strong>{total}</strong> {chips}</div>']
        if titles:
            items = ''.join(f'<li>{esc(t)}</li>' for t in titles[:12])
            parts.append(f'<div style="margin-top:6px;"><span class="l">Alert titles:</span><ul>{items}</ul></div>')
        if techs:
            parts.append('<div style="margin-top:6px;"><span class="l">ATT&CK:</span> '
                         + ' '.join(pill(t, '#555') for t in techs[:14]) + '</div>')
        if ents:
            parts.append(f'<div style="margin-top:6px;"><span class="l">Affected entities:</span> '
                         f'{esc(", ".join(str(x) for x in ents[:12]))}</div>')
        return f'<div class="section"><h2>🔔 Alert Correlation</h2>{"".join(parts)}</div>'

    # ─── CVE Correlation ──────────────────────────────────────────
    def _cve_correlation(self):
        c = self.cve
        if not c:
            return ''
        cves = as_list(c.get('cve_ids_found'))
        total_dev = c.get('total_unique_affected_devices', 0) or 0
        sb = c.get('cve_severity_breakdown', {}) or {}
        by_cve = c.get('affected_devices_by_cve', {}) or {}
        if not (cves or total_dev):
            return ''
        chips = ''
        for k in ('critical', 'high', 'medium', 'low'):
            n = sb.get(k, 0) or 0
            if n:
                chips += pill(f'{k.title()}: {n}', severity_color(k),
                              '#1a1a1a' if k in ('medium', 'low') else 'white')
        parts = [f'<div><span class="l">CVEs:</span> {len(cves)} · '
                 f'<span class="l">Affected devices:</span> <strong>{total_dev}</strong> {chips}</div>']
        if cves:
            parts.append('<div style="margin-top:6px;">' + ' '.join(pill(str(cid), '#c0392b') for cid in cves[:24]) + '</div>')
        if by_cve:
            rows = ''
            for cid, devs in list(by_cve.items())[:12]:
                dl = as_list(devs)
                names = []
                for d in dl[:6]:
                    if isinstance(d, dict):
                        names.append(d.get('deviceName') or d.get('device_name') or d.get('deviceId') or '?')
                    else:
                        names.append(str(d))
                rows += (f'<tr><td style="font-family:monospace;font-size:0.82em;">{esc(cid)}</td>'
                         f'<td style="text-align:center;">{len(dl)}</td>'
                         f'<td style="font-size:0.82em;">{esc(", ".join(names))}</td></tr>')
            parts.append('<table style="margin-top:6px;"><thead><tr><th>CVE</th>'
                         '<th style="text-align:center;">Devices</th><th>Sample</th></tr></thead>'
                         f'<tbody>{rows}</tbody></table>')
        return f'<div class="section"><h2>🩹 CVE Correlation</h2>{"".join(parts)}</div>'

    # ─── Organizational Exposure ──────────────────────────────────
    def _org_exposure(self):
        ex = self.exposure
        if not ex:
            return ''
        level = ex.get('exposure_level', '')
        total = ex.get('total_affected_devices', 0) or 0
        devs = as_list(ex.get('affected_device_list'))
        if not (level or total or devs):
            return ''
        lc = severity_color(level)
        rows = ''
        for d in devs[:20]:
            if isinstance(d, dict):
                name = d.get('deviceName') or d.get('device_name') or d.get('name') or '?'
                osp = d.get('osPlatform') or d.get('os') or ''
                rows += f'<tr><td>💻 {esc(name)}</td><td style="font-size:0.82em;">{esc(osp)}</td></tr>'
            else:
                rows += f'<tr><td>💻 {esc(d)}</td><td>—</td></tr>'
        table = (f'<table style="margin-top:6px;"><thead><tr><th>Device</th><th>OS</th></tr></thead>'
                 f'<tbody>{rows}</tbody></table>') if rows else ''
        return (f'<div class="section"><h2>🏢 Organizational Exposure</h2>'
                f'<div><span class="l">Exposure level:</span> '
                f'<span style="color:{lc};font-weight:bold;">{esc(level) or "—"}</span> · '
                f'<span class="l">Affected devices:</span> <strong>{total}</strong></div>{table}</div>')

    # ─── Recommendations / Risk factors ───────────────────────────
    def _recommendations(self):
        rf = as_list(self.risk.get('risk_factors'))
        mf = as_list(self.risk.get('mitigating_factors'))
        recs = as_list(self.exposure.get('recommended_actions'))
        if not (rf or mf or recs):
            return ''
        blocks = ''
        if rf:
            items = ''.join(f'<div class="alert" style="border-color:#f65314;">🔴 {esc(x)}</div>' for x in rf)
            blocks += f'<div><span class="l" style="font-weight:600;">Risk factors</span>{items}</div>'
        if mf:
            items = ''.join(f'<div class="alert" style="border-color:#7cbb00;">🟢 {esc(x)}</div>' for x in mf)
            blocks += f'<div style="margin-top:6px;"><span class="l" style="font-weight:600;">Mitigating factors</span>{items}</div>'
        if recs:
            items = ''.join(f'<li style="margin:4px 0;">{esc(x)}</li>' for x in recs)
            blocks += f'<div style="margin-top:6px;"><span class="l" style="font-weight:600;">Recommended actions</span><ol>{items}</ol></div>'
        return f'<div style="padding:12px;"><div class="section"><h2>💡 Assessment & Recommendations</h2>{blocks}</div></div>'

    # ─── Full HTML ────────────────────────────────────────────────
    def generate(self, output_path=None):
        ioc_disp = defang_ioc(self.ioc_value, self.ioc_type)
        verdict = self.ti.get('verdict', 'Unknown')
        overall = self.risk.get('overall_risk', '')
        now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
        vc = verdict_color(verdict)

        if not output_path:
            safe = re.sub(r'[^A-Za-z0-9._-]', '_', str(self.ioc_value))[:60]
            ts = datetime.now().strftime('%Y-%m-%d_%H%M%S')
            output_path = f'IoC_{self.ioc_type}_{safe}_{ts}.html'
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)

        left = '\n'.join(filter(None, [
            self._metadata_card(), self._verdict_card(), self._metrics()]))
        right = '\n'.join(filter(None, [
            self._threat_intel(), self._ip_enrichment(), self._activity(),
            self._alert_correlation(), self._cve_correlation(), self._org_exposure()]))

        risk_badge = ''
        if overall:
            risk_badge = (f'<span style="background:{severity_color(overall)};padding:3px 8px;'
                          f'border-radius:10px;font-size:0.8em;margin-left:6px;">{esc(overall)} risk</span>')

        html = f'''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>IoC {esc(self.ioc_type)} — {esc(ioc_disp)}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',Tahoma,sans-serif;font-size:13.5px;line-height:1.4;color:#e0e0e0;background:#1a1a1a;padding:12px}}
.ctr{{max-width:1600px;margin:0 auto;background:#1e1e1e;border-radius:7px;box-shadow:0 4px 20px rgba(0,0,0,0.5)}}
.wm{{position:fixed;top:0;left:0;right:0;background:linear-gradient(135deg,#dc3545,#c82333);color:white;padding:10px 20px;z-index:9999;box-shadow:0 2px 8px rgba(0,0,0,0.4);font-size:13px;font-weight:600;border-bottom:2px solid #ff6b6b;display:flex;justify-content:space-between;align-items:center}}
.hdr{{background:linear-gradient(135deg,#00a1f1,#0078d4);color:white;padding:18px 24px;display:flex;justify-content:space-between;align-items:center}}
.hdr h1{{font-size:1.4em;margin:0}}
.hdr .meta{{font-size:0.85em;text-align:right}}
.cnt{{display:grid;grid-template-columns:1.7fr 3.3fr;gap:12px;padding:12px}}
.section{{background:#252525;border-radius:5px;padding:14px;border-left:3px solid #00a1f1}}
.section h2{{font-size:1.15em;color:#00a1f1;margin-bottom:10px;padding-bottom:5px;border-bottom:1px solid #3a3a3a}}
.metrics{{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}}
.metric{{padding:12px;border-radius:5px;text-align:center}}
.mv{{font-size:2em;font-weight:bold;color:white}}.ml{{font-size:0.95em;color:rgba(255,255,255,0.9);margin-top:2px}}
table{{width:100%;border-collapse:collapse;font-size:0.95em;margin-top:4px}}
th{{background:#2a2a2a;color:#00a1f1;padding:7px 10px;text-align:left;font-weight:600;border-bottom:2px solid #3a3a3a}}
td{{padding:6px 10px;border-bottom:1px solid #2a2a2a}}tr:hover{{background:#2a2a2a}}
.l{{color:#b0b0b0;font-weight:500}}
.alert{{padding:9px 13px;margin:6px 0;border-left:3px solid;border-radius:4px;font-size:0.92em;background:#2a2a2a}}
ul,ol{{margin:6px 0 6px 22px;font-size:0.92em}}li{{margin:3px 0}}
.ftr{{background:#252525;padding:10px 20px;text-align:center;font-size:0.85em;color:#737373;border-top:1px solid #3a3a3a}}
</style></head><body>
<div class="wm"><div>🔒 <strong>CONFIDENTIAL — IoC INVESTIGATION</strong></div><div style="font-size:12px;">Generated by <strong>{get_user()}</strong> on <strong>{get_host()}</strong> | {now_str}</div></div>
<div class="ctr" style="margin-top:50px;">
  <div class="hdr"><div><h1>🔍 IoC <span style="opacity:0.7;font-weight:300;">[{esc((self.ioc_type or "").upper())}]</span> <span style="font-family:monospace;">{esc(ioc_disp)}</span></h1>
    <div style="font-size:1em;opacity:0.95;margin-top:4px;">
      <span style="background:{vc};padding:3px 8px;border-radius:10px;font-size:0.8em;">Verdict: {esc(verdict)}</span>
      {risk_badge}
    </div></div>
    <div class="meta"><div><strong>Generated:</strong> {now_str}</div><div><strong>Range:</strong> {fmt_ts(self.meta.get("date_range_start"))} → {fmt_ts(self.meta.get("date_range_end"))}</div></div></div>
  <div class="cnt"><div style="display:flex;flex-direction:column;gap:12px;">{left}</div><div style="display:flex;flex-direction:column;gap:12px;">{right}</div></div>
  {self._recommendations()}
  <div class="ftr"><strong style="color:#f65314;">⚠️ CONFIDENTIAL</strong> — IoC Investigation Report | [{esc((self.ioc_type or "").upper())}] {esc(ioc_disp)} | {now_str}</div>
</div></body></html>'''

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        return output_path


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 generate_html_report.py <json_file> [--output-dir DIR]")
        sys.exit(1)

    json_file = sys.argv[1]
    output_dir = '.'
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--output-dir' and i + 1 < len(sys.argv):
            output_dir = sys.argv[i + 1]
            i += 2
        else:
            i += 1

    with open(json_file, encoding='utf-8') as f:
        data = json.load(f)

    meta = data.get('investigation_metadata', {})
    ioc_type = meta.get('ioc_type', 'ioc')
    ioc_value = meta.get('ioc_value', 'unknown')
    safe = re.sub(r'[^A-Za-z0-9._-]', '_', str(ioc_value))[:60]
    ts = datetime.now().strftime('%Y-%m-%d_%H%M%S')
    output_path = os.path.join(output_dir, f'IoC_{ioc_type}_{safe}_{ts}.html')

    gen = IoCReportGenerator(data)
    path = gen.generate(output_path)
    print(f"✅ Report: {path}")


if __name__ == '__main__':
    main()
