"""Generate banner-light.svg, banner-dark.svg and pipeline.svg (animated, CSS only, respects reduced motion).

Run from the repo root:  python3 docs/media/src/make_svgs.py
"""
import os

OUT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SANS = '-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif'
MONO = "ui-monospace,SFMono-Regular,Menlo,Consolas,monospace"


def banner(theme: str) -> str:
    dark = theme == "dark"
    bg = "#0d1117" if dark else "#ffffff"
    fg = "#e6edf3" if dark else "#1f2328"
    mut = "#8b949e" if dark else "#59636e"
    acc = "#3fb950" if dark else "#1a7f37"
    warn = "#f85149" if dark else "#cf222e"
    grid = "#21262d" if dark else "#eaeef2"
    bars = "".join(f'<rect class="bar b{i}" x="{70 + i * 34}" y="{230 - h}" width="24" height="{h}" rx="5"/>'
                   for i, h in enumerate((36, 64, 92, 120)))
    # latency trace: calm, a bufferbloat spike (red flash), calm again
    trace = ("M330 232 L420 232 L436 224 L450 240 L464 232 L560 232 L574 190 L590 152 L606 210 L620 176 L640 232 "
             "L760 232 L772 224 L784 240 L796 232 L1210 232")
    grid_lines = "".join(f'<line x1="330" x2="1210" y1="{y}" y2="{y}"/>' for y in (152, 192, 232))
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1280 320" width="1280" height="320" role="img" aria-label="network-doctor: why is my internet bad? Ask Claude.">
<style>
  .bg{{fill:{bg}}} .grid{{stroke:{grid};stroke-width:1}}
  .bar{{fill:{acc};transform-origin:bottom;transform-box:fill-box;animation:grow 2.4s ease-in-out infinite}}
  .b1{{animation-delay:.15s}} .b2{{animation-delay:.3s}} .b3{{animation-delay:.45s}}
  .trace{{fill:none;stroke:{acc};stroke-width:4;stroke-linecap:round;stroke-linejoin:round;stroke-dasharray:1100;stroke-dashoffset:1100;animation:draw 4s ease-in-out infinite}}
  .spike{{fill:none;stroke:{warn};stroke-width:4;stroke-linecap:round;stroke-linejoin:round;opacity:0;animation:flash 4s ease-in-out infinite}}
  .title{{font:700 76px {MONO};fill:{fg};letter-spacing:-1px}}
  .tag{{font:500 30px {SANS};fill:{mut}}}
  .cursor{{fill:{acc};animation:blink 1.1s steps(1) infinite}}
  @keyframes grow{{0%,100%{{transform:scaleY(.35)}}50%{{transform:scaleY(1)}}}}
  @keyframes draw{{0%{{stroke-dashoffset:1100}}55%,100%{{stroke-dashoffset:0}}}}
  @keyframes flash{{0%,30%{{opacity:0}}38%,48%{{opacity:1}}60%,100%{{opacity:0}}}}
  @keyframes blink{{50%{{opacity:0}}}}
  @media (prefers-reduced-motion: reduce){{.bar,.trace,.spike,.cursor{{animation:none}} .trace{{stroke-dashoffset:0}}}}
</style>
<rect class="bg" width="1280" height="320" rx="18"/>
<g class="grid">{grid_lines}</g>
{bars}
<path class="trace" d="{trace}"/>
<path class="spike" d="M560 232 L574 190 L590 152 L606 210 L620 176 L640 232"/>
<text class="title" x="330" y="112">network-doctor<tspan class="cursor">_</tspan></text>
<text class="tag" x="330" y="290">Why is my internet bad? <tspan font-weight="700" fill="{acc}">Ask Claude.</tspan></text>
</svg>
'''


STAGES = [("Wi-Fi", "signal, channel, neighbours"), ("Link", "router ping, dropouts"),
          ("Load", "lag while up/downloading"), ("Calls", "UDP voice probe"), ("MTU + DNS", "black holes, slow DNS"),
          ("Router", "4G/5G, Wi-Fi, QoS"), ("Report", "ranked fixes")]


def pipeline() -> str:
    w, gap, x0, y = 150, 22, 14, 40
    parts = []
    for i, (t, sub) in enumerate(STAGES):
        x = x0 + i * (w + gap)
        parts.append(f'<g class="st s{i}"><rect x="{x}" y="{y}" width="{w}" height="86" rx="12"/>'
                     f'<text class="t" x="{x + w / 2}" y="{y + 38}">{t}</text>'
                     f'<text class="u" x="{x + w / 2}" y="{y + 62}">{sub}</text></g>')
        if i < len(STAGES) - 1:
            parts.append(f'<path class="ar" d="M{x + w + 3} {y + 43} l{gap - 8} 0 m-6 -5 l6 5 l-6 5"/>')
    total = len(STAGES) * 0.6 + 1.5
    delays = "".join(f".s{i} rect,.s{i} .t{{animation-delay:{i * 0.6:.1f}s}}" for i in range(len(STAGES)))
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1210 166" width="1210" height="166" role="img" aria-label="diagnosis pipeline: Wi-Fi, link, load, calls, MTU and DNS, router, report">
<style>
  rect{{fill:rgba(127,127,127,.08);stroke:rgba(127,127,127,.45);stroke-width:1.5;animation:lit {total:.1f}s ease-in-out infinite}}
  .t{{font:700 19px {SANS};fill:#8b949e;text-anchor:middle;animation:txt {total:.1f}s ease-in-out infinite}}
  .u{{font:400 12.5px {SANS};fill:#8b949e;text-anchor:middle}}
  .ar{{fill:none;stroke:#8b949e;stroke-width:2}}
  @keyframes lit{{0%{{fill:rgba(46,160,67,.08);stroke:rgba(127,127,127,.45)}}6%,14%{{fill:rgba(46,160,67,.28);stroke:#2ea043}}30%,100%{{fill:rgba(127,127,127,.08);stroke:rgba(127,127,127,.45)}}}}
  @keyframes txt{{0%{{fill:#8b949e}}6%,14%{{fill:#2ea043}}30%,100%{{fill:#8b949e}}}}
  {delays}
  @media (prefers-reduced-motion: reduce){{rect,.t{{animation:none}}}}
</style>
{"".join(parts)}
</svg>
'''


def social() -> str:
    """1280x640 social preview: the dark banner plus the supported router families."""
    inner = banner("dark").split(">", 1)[1].rsplit("</svg>", 1)[0]
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1280 640" width="1280" height="640">
<style>.bar,.trace,.spike,.cursor{{animation:none!important}} .trace{{stroke-dashoffset:0!important}}
.l1{{font:500 26px {SANS};fill:#8b949e}} .l2{{font:500 22px {SANS};fill:#6e7681}}</style>
<rect width="1280" height="640" fill="#0d1117"/>
<g transform="translate(0,80)">{inner}</g>
<text class="l1" x="330" y="520">Wi-Fi · bufferbloat · call quality · MTU · DNS · 4G/5G signal</text>
<text class="l2" x="330" y="562">Huawei · ZTE · TP-Link · ASUS · FRITZ!Box · MikroTik · OpenWrt</text>
</svg>
'''


def icon() -> str:
    """512x512 app icon: signal bars and a latency blip on a dark rounded square."""
    bars = "".join(f'<rect x="{96 + i * 72}" y="{372 - h}" width="52" height="{h}" rx="12" fill="#3fb950"/>'
                   for i, h in enumerate((70, 130, 190, 250)))
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">
<rect width="512" height="512" rx="112" fill="#0d1117"/>
{bars}
<path d="M70 430 L190 430 L210 410 L230 450 L250 430 L442 430" fill="none" stroke="#e6edf3" stroke-width="16" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
'''


def card(lines, sub="") -> str:
    """1280x720 title card for the hero video."""
    rows = "".join(f'<text x="640" y="{300 + i * 78}" class="h">{t}</text>' for i, t in enumerate(lines))
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1280 720" width="1280" height="720">
<style>.h{{font:700 56px {SANS};fill:#e6edf3;text-anchor:middle}} .s{{font:500 30px {MONO};fill:#3fb950;text-anchor:middle}}</style>
<rect width="1280" height="720" fill="#0d1117"/>{rows}
<text x="640" y="{330 + len(lines) * 78}" class="s">{sub}</text>
</svg>
'''


if __name__ == "__main__":
    for theme in ("light", "dark"):
        with open(os.path.join(OUT, f"banner-{theme}.svg"), "w") as f:
            f.write(banner(theme))
    with open(os.path.join(OUT, "pipeline.svg"), "w") as f:
        f.write(pipeline())
    with open(os.path.join(OUT, "src", "social.svg"), "w") as f:
        f.write(social())
    with open(os.path.join(OUT, "src", "icon.svg"), "w") as f:
        f.write(icon())
    cards = {"card-1": (["“My voice keeps breaking", "in meetings.”"], "network-doctor measures why"),
             "card-2": (["Calls break when the line is busy:"], "latency under load (bufferbloat)"),
             "card-3": (["Then it reads your router", "and plans the fix"], "nothing changes until you approve"),
             "card-4": (["Install in Claude Code"], "/plugin marketplace add dav-ayman/network-doctor")}
    for name, (lines, sub) in cards.items():
        with open(os.path.join(OUT, "src", f"{name}.svg"), "w") as f:
            f.write(card(lines, sub))
    print("wrote banner-light.svg, banner-dark.svg, pipeline.svg, src/social.svg")
