"""Animated SVG figures for the README and docs, rendered from verified release statistics.

GitHub shows repository SVGs as images: CSS animation works, scripts and hover do not.
Every figure has a light and a dark variant and stops moving under reduced motion; its
description carries every value it shows.
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
# The rest frame of every animation is the static figure.
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
.draw {{ stroke-dasharray: 1; animation: draw .6s {EASE} backwards; }}
@keyframes rise {{ from {{ opacity: 0; transform: translateY(8px); }} }}
@keyframes draw {{ from {{ stroke-dashoffset: 1; }} }}
@keyframes grow {{ from {{ transform: scaleX(0); }} }}
@keyframes fade {{ from {{ opacity: 0; }} }}
@keyframes pulse {{ from {{ opacity: .5; transform: scale(1); }} to {{ opacity: 0; transform: scale(2.8); }} }}
@media (prefers-reduced-motion: reduce) {{ * {{ animation: none !important; }} }}
</style>"""


def document(height, title, description, theme, body, extra_style=""):
    return "\n".join([
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{height}" '
        f'viewBox="0 0 {WIDTH} {height}" role="img" aria-labelledby="title desc">',
        f'<title id="title">{escape(title)}</title>', f'<desc id="desc">{escape(description)}</desc>',
        style(theme), *([f"<style>{extra_style}</style>"] if extra_style else []),
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
    # Unique detections lead: entries count every SQL variant of a rule.
    tiles = [("Unique Windows detections", summary["windows_unique"], 40, 24),
             ("Rule entries", summary["windows_rules"], 28, 280),
             ("Linux rules", summary["linux"], 28, 419),
             ("Correlations", summary["correlations"], 28, 558),
             ("Last change (UTC)", summary["updated"], 22, 697)]
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


def node(x, y, width, height, label, value, notes, theme, wait=0, accent=False, size=20):
    """A stage or file: a label, its headline value, and short notes."""
    stroke = f'stroke="{theme["series"]}" stroke-width="1.5"' if accent else f'stroke="{theme["rule"]}"'
    lines = [f'<rect x="{x}" y="{y}" width="{width}" height="{height}" rx="8" fill="{theme["surface"]}" {stroke}/>',
             f'<text x="{x + 12}" y="{y + 21}" font-size="12" class="secondary">{escape(label)}</text>',
             f'<text x="{x + 12}" y="{y + 46}" font-size="{size}" font-weight="600">{escape(value)}</text>',
             *(f'<text x="{x + 12}" y="{y + 65 + 14 * index}" font-size="11" class="secondary">{escape(note)}</text>'
               for index, note in enumerate(notes))]
    return f'<g class="rise"{delay(wait)}>' + "".join(lines) + "</g>"


def connector(points, theme, wait=0, dashed=False):
    """An arrow along axis-aligned segments, drawn once; dashed for the fallback path."""
    path = "M" + "L".join(f"{x:.1f} {y:.1f}" for x, y in points)
    (fx, fy), (x, y) = points[-2], points[-1]
    if fy == y:
        step = 1 if x > fx else -1
        head = f"M{x:.1f} {y:.1f}L{x - 7 * step:.1f} {y - 4:.1f}L{x - 7 * step:.1f} {y + 4:.1f}Z"
    else:
        step = 1 if y > fy else -1
        head = f"M{x:.1f} {y:.1f}L{x - 4:.1f} {y - 7 * step:.1f}L{x + 4:.1f} {y - 7 * step:.1f}Z"
    stroke = f'stroke="{theme["muted"]}" stroke-width="1.5" fill="none"'
    line = (f'<path class="fade"{delay(wait)} d="{path}" {stroke} stroke-dasharray="4 4"/>' if dashed
            else f'<path class="draw"{delay(wait)} pathLength="1" d="{path}" {stroke}/>')
    return line + f'<path class="fade"{delay(wait + 400)} d="{head}" fill="{theme["muted"]}"/>'


def sweep(name, boxes, color, start, step=350, cycle=7000):
    """Outlines that light each box in turn, then rest hidden: the flow, repeated.

    They are invisible unless animated, so reduced motion and the rest frame show none.
    """
    share = 100 * step / cycle
    css = (f"@keyframes {name} {{ 0% {{ opacity: 0; }} {share:.1f}% {{ opacity: 1; }} "
           f"{2 * share:.1f}%, 100% {{ opacity: 0; }} }} "
           f".{name} {{ opacity: 0; animation: {name} {cycle}ms ease-in-out infinite; }}")
    return css, [f'<rect class="{name}"{delay(start + index * step)} x="{x}" y="{y}" width="{width}" '
                 f'height="{height}" rx="8" fill="none" stroke="{color}" stroke-width="2"/>'
                 for index, (x, y, width, height) in enumerate(boxes)]


def pipeline(counts, name):
    """How a rule is published: the daily stages, with the current release's counts."""
    theme = THEMES[name]
    gap, top, height = 12, 84, 104
    stages = [
        ("Fetch", counts["sources"], ["sources, each at", "a pinned commit"], 116),
        ("Read", counts["documents"], ["Sigma documents,", f"{counts['skipped']} others skipped"], 116),
        ("Convert", f"{counts['profiles']} profiles", ["queries prepared", "in SQLite"], 116),
        ("Left out", counts["left_out"], [f"{counts['policy']} by policy", f"{counts['reviewed']} after review"], 116),
        ("Publish", counts["detections"], ["Windows rules", f"+{counts['linux']} Linux",
                                           f"+{counts['correlations']} correlations"], 116),
        ("Combine", counts["windows_all"], ["entries in", "rules_windows_all.json"], 172),
    ]
    left, x = [], 24
    for *_, width in stages:
        left.append(x)
        x += width + gap
    middle, gate, right = top + height / 2, left[3] + 58, left[-1] + stages[-1][3]
    below = top + height + 34
    # After the stages appear, the flow lights them in turn; at the review gate a
    # source either publishes or, with an unreviewed failure, keeps its last rules.
    flow, lit = sweep("flow", [(x, top, width, height) for x, (*_, width) in zip(left, stages)],
                      theme["series"], 2400)
    held, warned = sweep("held", [(left[3], below, right - left[3], 48)], STATUS["warning"], 2400 + 4 * 350)
    body = ['<text x="24" y="36" font-size="16" font-weight="600">How a rule is published</text>',
            '<text x="24" y="56" font-size="12" class="secondary">Every source, daily at 01:23 UTC. '
            'Counts from the current release; one rule can yield several entries.</text>']
    for index, (label, value, notes, width) in enumerate(stages):
        body.append(node(left[index], top, width, height, label, value, notes, theme, wait=100 + index * 160,
                         accent=index == len(stages) - 1, size=18))
        if index:
            body.append(connector([(left[index] - gap, middle), (left[index], middle)], theme,
                                  wait=180 + index * 160))
    stale = counts["stale"]
    status = f"{stale} of {counts['sources']} sources stale now" if stale else f"All {counts['sources']} sources current"
    body.extend([connector([(gate, top + height), (gate, below)], theme, wait=1200, dashed=True),
                 f'<g class="rise"{delay(1300)}>'
                 f'<rect x="{left[3]}" y="{below}" width="{right - left[3]}" height="48" rx="8" '
                 f'fill="{theme["surface"]}" stroke="{theme["rule"]}" stroke-dasharray="4 4"/>'
                 f'<text x="{left[3] + 12}" y="{below + 20}" font-size="12">Unreviewed failure: the source keeps '
                 f'its last good rules</text>'
                 f'<text x="{left[3] + 12}" y="{below + 37}" font-size="11" class="secondary">{escape(status)}</text>'
                 '</g>', *lit, *warned])
    return document(below + 72, "How a rule is published", counts["alt"], theme, body, f"{flow} {held}")


def files(count):
    return f"{count} file" + ("" if count == 1 else "s")


def family_map(families, name):
    """How the published Windows files build on each other, with entry counts."""
    theme = THEMES[name]
    column, box = (24, 330, 636), 200
    rows = {"sysmon": 80, "generic": 168, "native": 256}
    body = ['<text x="24" y="36" font-size="16" font-weight="600">From profiles to files</text>',
            '<text x="24" y="56" font-size="12" class="secondary">Entries across every source. One rule can have '
            'a Sysmon and a Generic variant; identical SQL is kept once.</text>']
    for index, (profile, label, note) in enumerate((
            ("sysmon", "Sysmon", "categories as Sysmon events"),
            ("generic", "Generic", "as Windows audit events (4688…)"),
            ("native", "Native", "Windows channels as written"))):
        body.append(node(column[0], rows[profile], box, 76, f"{label} · {files(families[profile]['files'])}",
                         families[profile]["entries"], [note], theme, wait=100 + index * 120))
    merged_top, all_top = 124, 196
    body.append(node(column[1], merged_top, box, 76, f"Merged · {files(families['merged']['files'])}",
                     families["merged"]["entries"], [f"−{families['shared']} identical in both"], theme, wait=520))
    body.append(node(column[2], all_top, box, 104, "rules_windows_all.json", families["windows_all"],
                     [f"{families['unique']} unique detections", f"{families['duplicates']} cross-source duplicates",
                      "dropped, SigmaHQ kept first"], theme, wait=820, accent=True))
    left_end, merged_mid, all_mid = column[0] + box, merged_top + 38, all_top + 52
    body.extend([
        connector([(left_end, rows["sysmon"] + 38), (left_end + 50, rows["sysmon"] + 38),
                   (left_end + 50, merged_mid - 10), (column[1], merged_mid - 10)], theme, wait=420),
        connector([(left_end, rows["generic"] + 38), (left_end + 50, rows["generic"] + 38),
                   (left_end + 50, merged_mid + 10), (column[1], merged_mid + 10)], theme, wait=460),
        connector([(column[1] + box, merged_mid), (column[1] + box + 50, merged_mid),
                   (column[1] + box + 50, all_mid - 12), (column[2], all_mid - 12)], theme, wait=720),
        connector([(left_end, rows["native"] + 38), (column[1] + box + 70, rows["native"] + 38),
                   (column[1] + box + 70, all_mid + 12), (column[2], all_mid + 12)], theme, wait=760),
        f'<line x1="24" y1="352" x2="{WIDTH - 24}" y2="352" stroke="{theme["rule"]}"/>'])
    body.append(node(column[0], 368, 398, 76, f"Linux · {files(families['linux']['files'])}",
                     families["linux"]["entries"], ["Sigma field names; never combined with Windows"], theme,
                     wait=1000))
    body.append(node(438, 368, 398, 76, f"Experimental correlations · {files(families['correlations']['files'])}",
                     families["correlations"]["entries"], ["experimental/, for Zircolite 4.1 or newer"], theme,
                     wait=1100))
    return document(468, "From profiles to files", families["alt"], theme, body)


def status_strip(sources, name):
    """One labeled dot per source; status is written, never colour alone."""
    theme = THEMES[name]
    per_row, cell, top, step = 5, (WIDTH - 48) / 5, 22, 46
    body = []
    for index, (source, status, since) in enumerate(sources):
        x, y = 24 + (index % per_row) * cell, top + (index // per_row) * step
        label = status if status != "stale" or not since else f"stale since {since}"
        if status == "current":
            dot = f'<circle cx="{x + 6:.1f}" cy="{y + 6}" r="5" fill="{STATUS["good"]}"/>'
        elif status == "stale":
            dot = (f'<circle class="pulse" cx="{x + 6:.1f}" cy="{y + 6}" r="5" fill="{STATUS["warning"]}"/>'
                   f'<circle cx="{x + 6:.1f}" cy="{y + 6}" r="5" fill="{STATUS["warning"]}"/>')
        else:
            dot = f'<circle cx="{x + 6:.1f}" cy="{y + 6}" r="4.25" fill="none" stroke="{theme["muted"]}" stroke-width="1.5"/>'
        body.append(f'<g class="fade"{delay(60 + index * 50)}>{dot}'
                    f'<text x="{x + 18:.1f}" y="{y + 10}" font-size="12">{escape(source)}</text>'
                    f'<text x="{x + 18:.1f}" y="{y + 25}" font-size="11" class="secondary">{escape(label)}</text></g>')
    rows = -(-len(sources) // per_row)
    description = ", ".join(f"{source} {status}" + (f" since {since}" if since and status != "current" else "")
                            for source, status, since in sources)
    return document(top + rows * step, "Source status", f"Source status: {description}.", theme, body)
