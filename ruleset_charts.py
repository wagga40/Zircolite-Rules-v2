"""Animated SVG figures for the README and dashboard, rendered from verified release statistics.

GitHub shows repository SVGs as images: CSS animation works, scripts and hover do not.
Every figure has a light and a dark variant and stops moving under reduced motion.
"""

from html import escape

from rule_conversion import LEVELS

FONT = 'system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif'
WIDTH = 860
# Light and dark steps of one validated palette; dark is selected, not inverted.
THEMES = {
    "light": {"surface": "#fcfcfb", "border": "rgba(11,11,11,0.10)", "primary": "#0b0b0b",
              "secondary": "#52514e", "muted": "#898781", "rule": "#e1e0d9", "series": "#2a78d6",
              # Severity, informational to critical: one hue, ordinal, light end clears the surface.
              "severity": ("#86b6ef", "#5598e7", "#2a78d6", "#1c5cab", "#104281")},
    "dark": {"surface": "#1a1a19", "border": "rgba(255,255,255,0.10)", "primary": "#f0efec",
             "secondary": "#c3c2b7", "muted": "#898781", "rule": "#2c2c2a", "series": "#3987e5",
             "severity": ("#184f95", "#256abf", "#3987e5", "#6da7ec", "#9ec5f4")},
}
STATUS = {"good": "#0ca30c", "warning": "#fab219"}
EASE = "cubic-bezier(.2,.7,.2,1)"


def style(theme):
    return f"""<style>
text {{ font-family: {FONT}; fill: {theme['primary']}; }}
.secondary {{ fill: {theme['secondary']}; }}
.muted {{ fill: {theme['muted']}; }}
.rise {{ animation: rise .7s {EASE} backwards; }}
.grow {{ transform-box: fill-box; transform-origin: left center; animation: grow .9s {EASE} backwards; }}
.fade {{ animation: fade .5s ease-out backwards; }}
.pulse {{ transform-box: fill-box; transform-origin: center; animation: pulse 2.4s ease-out infinite; }}
@keyframes rise {{ from {{ opacity: 0; transform: translateY(8px); }} }}
@keyframes grow {{ from {{ transform: scaleX(0); }} }}
@keyframes fade {{ from {{ opacity: 0; }} }}
@keyframes pulse {{ from {{ opacity: .5; transform: scale(1); }} to {{ opacity: 0; transform: scale(2.8); }} }}
@media (prefers-reduced-motion: reduce) {{ * {{ animation: none !important; }} }}
</style>"""


def document(height, title, description, theme, body):
    return "\n".join([
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{height}" '
        f'viewBox="0 0 {WIDTH} {height}" role="img" aria-labelledby="title desc">',
        f'<title id="title">{escape(title)}</title>', f'<desc id="desc">{escape(description)}</desc>',
        style(theme),
        f'<rect x="0.5" y="0.5" width="{WIDTH - 1}" height="{height - 1}" rx="12" '
        f'fill="{theme["surface"]}" stroke="{theme["border"]}"/>',
        *body, "</svg>", ""])


def delay(milliseconds):
    return f' style="animation-delay:{milliseconds}ms"'


def bar(x, y, width, height, fill, css="grow", wait=0):
    """A bar with a 4px rounded data end and a square baseline."""
    width = max(width, 1.0)
    radius = min(4.0, width, height / 2)
    return (f'<path class="{css}"{delay(wait)} fill="{fill}" d="M{x:.1f} {y:.1f}H{x + width - radius:.1f}'
            f'Q{x + width:.1f} {y:.1f} {x + width:.1f} {y + radius:.1f}V{y + height - radius:.1f}'
            f'Q{x + width:.1f} {y + height:.1f} {x + width - radius:.1f} {y + height:.1f}H{x:.1f}Z"/>')


def overview(summary, name):
    """The README and dashboard headline: status, stat tiles, and the severity split."""
    theme = THEMES[name]
    current, total = summary["current"], summary["sources"]
    status = STATUS["good" if current == total else "warning"]
    body = ['<text x="24" y="38" font-size="17" font-weight="600">Zircolite rules</text>',
            f'<circle class="pulse" cx="620" cy="32" r="5" fill="{status}"/>',
            f'<circle cx="620" cy="32" r="5" fill="{status}"/>',
            f'<text x="634" y="37" font-size="13" class="secondary">{current} of {total} sources current</text>']
    # Tile boundaries: a wide hero tile, then four equal tiles separated by hairlines.
    tiles = [("Rules in rules_windows_all.json", summary["windows_rules"], 40, 24),
             ("Unique detections", summary["windows_unique"], 28, 280),
             ("Linux rules", summary["linux"], 28, 419),
             ("Correlations", summary["correlations"], 28, 558),
             ("Updated (UTC)", summary["updated"], 22, 697)]
    for index, (label, value, size, x) in enumerate(tiles):
        if index:
            body.append(f'<line x1="{x}" y1="68" x2="{x}" y2="122" stroke="{theme["rule"]}"/>')
        body.append(f'<g transform="translate({x + (16 if index else 0)} 0)"><g class="rise"{delay(80 + index * 90)}>'
                    f'<text y="78" font-size="12" class="secondary">{escape(label)}</text>'
                    f'<text y="{86 + size}" font-size="{size}" font-weight="600">{escape(value)}</text></g></g>')
    severity = summary["severity"]
    if sum(severity.values()):
        body.append('<text x="24" y="160" font-size="12" class="secondary">'
                    'Severity of unique detections in rules_windows_all.json</text>')
        total_rules, x, span = sum(severity.values()), 24.0, WIDTH - 48
        visible = [level for level in LEVELS if severity[level]]
        gaps = 2 * (len(visible) - 1)
        for index, level in enumerate(visible):
            width = max((span - gaps) * severity[level] / total_rules, 2)
            color = theme["severity"][LEVELS.index(level)]
            if level == visible[-1]:
                body.append(bar(x, 172, width, 12, color, wait=500 + index * 140))
            else:
                body.append(f'<rect class="grow"{delay(500 + index * 140)} x="{x:.1f}" y="172" '
                            f'width="{width:.1f}" height="12" fill="{color}"/>')
            x += width + 2
        for index, level in enumerate(LEVELS):
            left = 24 + index * (WIDTH - 48) / len(LEVELS)
            body.append(f'<g class="fade"{delay(900 + index * 80)}>'
                        f'<rect x="{left:.1f}" y="200" width="10" height="10" rx="2" '
                        f'fill="{theme["severity"][index]}"/>'
                        f'<text x="{left + 16:.1f}" y="209.5" font-size="12" class="secondary">'
                        f'{level.capitalize()} <tspan class="muted">{severity[level]:,}</tspan></text></g>')
    height = 228 if sum(severity.values()) else 148
    return document(height, "Zircolite rules overview", summary["alt"], theme, body)


def bar_chart(title, subtitle, rows, name):
    """One series as horizontal bars, labeled at the tip; muted rows are de-emphasized."""
    theme = THEMES[name]
    top, step, thickness, left, right = 82, 24, 14, 224, 72
    span = WIDTH - left - right
    peak = max((value for _, value, _ in rows), default=0) or 1
    body = [f'<text x="24" y="36" font-size="16" font-weight="600">{escape(title)}</text>',
            f'<text x="24" y="56" font-size="12" class="secondary">{escape(subtitle)}</text>',
            f'<line x1="{left}" y1="{top - 6}" x2="{left}" y2="{top + len(rows) * step - 4}" '
            f'stroke="{theme["rule"]}"/>']
    for index, (label, value, muted) in enumerate(rows):
        y = top + index * step
        width = span * value / peak
        text = label if len(label) <= 30 else label[:29] + "…"
        body.extend([
            f'<text x="{left - 10}" y="{y + 11}" font-size="12" text-anchor="end" class="secondary">'
            f'{escape(text)}</text>',
            bar(left, y, width, thickness, theme["muted"] if muted else theme["series"], wait=120 + index * 45),
            f'<text class="fade secondary"{delay(700 + index * 45)} x="{left + max(width, 1) + 8:.1f}" '
            f'y="{y + 11}" font-size="12">{value:,}</text>'])
    description = subtitle + ". " + "; ".join(f"{label}: {value:,}" for label, value, _ in rows) + "."
    return document(top + len(rows) * step + 14, title, description, theme, body)
