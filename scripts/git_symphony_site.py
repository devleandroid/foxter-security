import html
import json
from pathlib import Path
from urllib.parse import urlsplit


def _safe_repository_url(repository_url):
    if not repository_url:
        return ""
    parsed = urlsplit(repository_url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("A URL do repositório precisa usar HTTPS.")
    return repository_url.rstrip("/")


def render_score_svg(events, repository_url=""):
    """Renderiza uma partitura compacta em SVG, adequada para o README."""
    width = 1200
    height = 540
    margin = 42
    score_events = events[-12:]
    repository_url = _safe_repository_url(repository_url)

    parts = [
        (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
            f'role="img" aria-labelledby="title description">'
        ),
        "<title id=\"title\">Git Symphony — piano dos commits</title>",
        (
            '<desc id="description">Acordes gerados a partir do histórico Git '
            'em um piano digital.</desc>'
        ),
        """
        <defs>
          <linearGradient id="background" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stop-color="#101528"/>
            <stop offset="1" stop-color="#171b32"/>
          </linearGradient>
          <linearGradient id="accent" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0" stop-color="#a78bfa"/>
            <stop offset="1" stop-color="#67e8f9"/>
          </linearGradient>
          <filter id="glow" x="-100%" y="-100%" width="300%" height="300%">
            <feGaussianBlur stdDeviation="5" result="blur"/>
            <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>
        </defs>
        """,
        f'<rect width="{width}" height="{height}" rx="28" fill="url(#background)"/>',
        '<text x="42" y="56" fill="#a78bfa" font-family="sans-serif" '
        'font-size="13" font-weight="700" letter-spacing="3">GIT SYMPHONY</text>',
        '<text x="42" y="93" fill="#f8fafc" font-family="sans-serif" '
        'font-size="25" font-weight="700">A trilha sonora do seu código</text>',
        (
            f'<text x="{width - margin}" y="57" text-anchor="end" fill="#94a3b8" '
            'font-family="sans-serif" font-size="13">'
            f'{len(events)} commits · {len(score_events)} acordes em destaque</text>'
        ),
    ]

    plot_left = margin
    plot_right = width - margin
    plot_bottom = 340
    for midi_note in (60, 67, 72, 79, 84, 91):
        y = plot_bottom - (midi_note - 60) * 3.45
        parts.append(
            f'<line x1="{plot_left}" y1="{y:.1f}" x2="{plot_right}" y2="{y:.1f}" '
            'stroke="#2a3150" stroke-width="1"/>'
        )

    if score_events:
        column_width = (plot_right - plot_left) / len(score_events)
        root_points = []
        for index, event in enumerate(score_events):
            x = plot_left + column_width * (index + 0.5)
            root = event["notes"][0]
            root_y = plot_bottom - (root - 60) * 3.45
            root_points.append(f"{x:.1f},{root_y:.1f}")
        parts.append(
            f'<polyline points="{" ".join(root_points)}" fill="none" '
            'stroke="url(#accent)" stroke-width="2" opacity="0.55"/>'
        )

        for index, event in enumerate(score_events):
            center = plot_left + column_width * (index + 0.5)
            latest = index == len(score_events) - 1
            color = "#67e8f9" if latest else "#a78bfa"
            for note in event["notes"]:
                y = plot_bottom - (note - 60) * 3.45
                parts.append(
                    f'<circle cx="{center:.1f}" cy="{y:.1f}" r="6" fill="{color}" '
                    f'filter="{"url(#glow)" if latest else "none"}"/>'
                )
            parts.append(
                f'<text x="{center:.1f}" y="365" text-anchor="middle" fill="#f8fafc" '
                f'font-family="sans-serif" font-size="13" font-weight="700">'
                f'{html.escape(event["chord"])}</text>'
            )
            commit_label = html.escape(event["hash"][:7])
            if repository_url:
                parts.append(
                    f'<a href="{html.escape(repository_url, quote=True)}/commit/'
                    f'{commit_label}" target="_blank">'
                    f'<text x="{center:.1f}" y="383" text-anchor="middle" '
                    'fill="#94a3b8" font-family="monospace" font-size="10">'
                    f'{commit_label}</text></a>'
                )
            else:
                parts.append(
                    f'<text x="{center:.1f}" y="383" text-anchor="middle" '
                    'fill="#94a3b8" font-family="monospace" font-size="10">'
                    f'{commit_label}</text>'
                )

    key_start = 60
    key_end = 96
    key_top = 414
    key_height = 88
    white_notes = {0, 2, 4, 5, 7, 9, 11}
    black_notes = {1, 3, 6, 8, 10}
    white_count = sum(
        note % 12 in white_notes for note in range(key_start, key_end)
    )
    white_width = (width - 2 * margin) / white_count
    black_width = white_width * 0.62
    active_notes = set(score_events[-1]["notes"]) if score_events else set()
    white_index = 0

    for note in range(key_start, key_end):
        pitch = note % 12
        if pitch in white_notes:
            fill = "#b6efff" if note in active_notes else "#f1f5f9"
            parts.append(
                f'<rect x="{margin + white_index * white_width:.2f}" y="{key_top}" '
                f'width="{white_width:.2f}" height="{key_height}" rx="2" '
                f'fill="{fill}" stroke="#475569" stroke-width="1"/>'
            )
            if pitch == 0:
                octave = note // 12 - 1
                parts.append(
                    f'<text x="{margin + white_index * white_width + 5:.2f}" '
                    f'y="{key_top + key_height - 8}" fill="#64748b" '
                    'font-family="sans-serif" font-size="10">C'
                    f'{octave}</text>'
                )
            white_index += 1
        elif pitch in black_notes:
            x = margin + white_index * white_width - black_width / 2
            fill = "#a78bfa" if note in active_notes else "#20263b"
            parts.append(
                f'<rect x="{x:.2f}" y="{key_top}" width="{black_width:.2f}" '
                'height="54" rx="3" '
                f'fill="{fill}" stroke="#080b14" stroke-width="1"/>'
            )

    parts.extend(
        [
            '<text x="42" y="525" fill="#64748b" font-family="sans-serif" '
            'font-size="11">Cada acorde nasce do hash e da mensagem de um commit.</text>',
            "</svg>",
        ]
    )
    return "\n".join(parts)


def render_player_html(events, svg_href, midi_href, repository_url, tempo):
    repository_url = _safe_repository_url(repository_url)
    composition = json.dumps(
        {"events": events, "tempo": tempo},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    composition = (
        composition.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )
    svg_href = html.escape(svg_href, quote=True)
    midi_href = html.escape(midi_href, quote=True)
    repository_url = json.dumps(repository_url)

    return f"""<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#101528">
  <meta name="description" content="Uma sinfonia feita com os commits deste repositório.">
  <title>Git Symphony — a trilha sonora do código</title>
  <style>
    :root {{ color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0; min-height: 100vh; color: #e5e7eb;
      background: radial-gradient(ellipse at 50% -20%, #35305e 0, #101528 55%);
    }}
    main {{ width: min(1120px, calc(100% - 32px)); margin: 0 auto; padding: 48px 0 64px; }}
    .eyebrow {{ color: #a78bfa; font-size: .75rem; font-weight: 800; letter-spacing: .22em; }}
    h1 {{ margin: 12px 0 8px; color: #fff; font-size: clamp(2rem, 6vw, 3.5rem); letter-spacing: -.045em; }}
    .intro {{ margin: 0; color: #aab3c8; }}
    .panel {{
      margin-top: 28px; overflow: hidden; border: 1px solid #ffffff18;
      border-radius: 24px; background: #13192bea;
      box-shadow: 0 28px 90px #05071480;
    }}
    .transport {{ display: flex; align-items: center; gap: 18px; padding: 22px 26px; }}
    button {{
      display: inline-flex; align-items: center; gap: 10px; padding: 13px 20px;
      border: 0; border-radius: 999px; background: linear-gradient(110deg, #a78bfa, #67e8f9);
      color: #101528; font: inherit; font-weight: 800; cursor: pointer;
    }}
    button:disabled {{ opacity: .45; cursor: not-allowed; }}
    button:focus-visible, a:focus-visible {{ outline: 3px solid #67e8f9; outline-offset: 4px; }}
    #status {{ color: #aab3c8; font-size: .9rem; }}
    .stats {{ display: flex; flex-wrap: wrap; gap: 8px; margin-left: auto; }}
    .pill {{ border: 1px solid #ffffff18; border-radius: 999px; padding: 7px 11px; color: #c4b5fd; font-size: .78rem; }}
    .score {{ padding: 0 18px 18px; }}
    .score img {{ display: block; width: 100%; border-radius: 15px; }}
    .actions {{ display: flex; flex-wrap: wrap; justify-content: space-between; gap: 16px; padding: 0 26px 24px; }}
    a {{ color: #67e8f9; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    h2 {{ margin: 34px 0 14px; color: #fff; font-size: 1.1rem; }}
    ol {{ display: grid; gap: 8px; margin: 0; padding: 0; list-style: none; }}
    li {{
      display: grid; grid-template-columns: 46px 72px minmax(0, 1fr) auto;
      align-items: center; gap: 12px; padding: 12px 14px;
      border: 1px solid #ffffff10; border-radius: 12px; background: #151c30;
    }}
    li[aria-current="true"] {{ border-color: #67e8f9; background: #1c2940; }}
    .number {{ color: #71809b; font: .78rem ui-monospace, monospace; }}
    .chord {{ color: #c4b5fd; font-weight: 800; }}
    .message {{ overflow: hidden; color: #dbe2ef; text-overflow: ellipsis; white-space: nowrap; }}
    .author {{ color: #8290a9; font-size: .78rem; }}
    footer {{ margin-top: 30px; color: #64748b; font-size: .82rem; }}
    @media (max-width: 620px) {{
      main {{ padding-top: 30px; }}
      .transport {{ align-items: flex-start; flex-wrap: wrap; }}
      .stats {{ margin-left: 0; }}
      li {{ grid-template-columns: 38px 58px minmax(0, 1fr); gap: 8px; }}
      .author {{ display: none; }}
      .actions {{ padding-inline: 18px; }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <div class="eyebrow">GIT SYMPHONY</div>
      <h1>O som de cada mudança.</h1>
      <p class="intro">Cada commit vira um acorde. Esta composição acompanha as versões do projeto.</p>
    </header>
    <section class="panel" aria-label="Player da sinfonia do Git">
      <div class="transport">
        <button id="play" type="button" aria-label="Reproduzir sinfonia">
          <span aria-hidden="true">▶</span><span>Play</span>
        </button>
        <span id="status" role="status" aria-live="polite">Pronto para tocar</span>
        <div class="stats">
          <span class="pill" id="commit-count"></span>
          <span class="pill">{tempo} BPM</span>
        </div>
      </div>
      <div class="score">
        <img src="{svg_href}" alt="Partitura em piano gerada pelos commits">
      </div>
      <div class="actions">
        <a href="{midi_href}" download>Baixar arquivo MIDI</a>
        <a id="repository-link" href="#" hidden>Ver repositório</a>
      </div>
    </section>
    <section aria-labelledby="history-title">
      <h2 id="history-title">Acordes da composição</h2>
      <ol id="events"></ol>
    </section>
    <footer>Gerado automaticamente a partir do histórico Git desta versão. O áudio começa somente ao clicar em Play.</footer>
  </main>
  <script id="composition" type="application/json">{composition}</script>
  <script>
    const composition = JSON.parse(document.getElementById("composition").textContent);
    const repositoryUrl = {repository_url};
    const playButton = document.getElementById("play");
    const statusLabel = document.getElementById("status");
    const eventList = document.getElementById("events");
    const events = composition.events;
    let audioContext;
    let timer;
    let sources = [];
    let playbackId = 0;
    let isPlaying = false;

    document.getElementById("commit-count").textContent = `${{events.length}} commits`;
    const repositoryLink = document.getElementById("repository-link");
    if (repositoryUrl) {{
      repositoryLink.href = repositoryUrl;
      repositoryLink.hidden = false;
    }}

    events.forEach((event, index) => {{
      const row = document.createElement("li");
      row.id = `commit-${{index}}`;
      const number = document.createElement("span");
      number.className = "number";
      number.textContent = String(index + 1).padStart(2, "0");
      const chord = document.createElement("span");
      chord.className = "chord";
      chord.textContent = event.chord;
      const message = document.createElement("span");
      message.className = "message";
      message.textContent = event.message;
      message.title = event.message;
      const author = document.createElement("span");
      author.className = "author";
      author.textContent = event.author;
      row.append(number, chord, message, author);
      eventList.append(row);
    }});
    playButton.disabled = events.length === 0;

    function stopPlayback(message = "Reprodução interrompida") {{
      playbackId += 1;
      window.clearTimeout(timer);
      sources.forEach(source => {{
        try {{ source.stop(); }} catch (error) {{
          if (error.name !== "InvalidStateError") throw error;
        }}
      }});
      sources = [];
      isPlaying = false;
      document.querySelectorAll("#events li").forEach(row => row.removeAttribute("aria-current"));
      playButton.innerHTML = '<span aria-hidden="true">▶</span><span>Play</span>';
      playButton.setAttribute("aria-label", "Reproduzir sinfonia");
      statusLabel.textContent = message;
    }}

    function playEvent(index, activePlayback) {{
      if (activePlayback !== playbackId) return;
      if (index >= events.length) {{
        stopPlayback("Sinfonia concluída");
        return;
      }}
      const event = events[index];
      const duration = Math.max(0.18, event.duration * 60 / composition.tempo);
      const start = audioContext.currentTime;
      const row = document.getElementById(`commit-${{index}}`);
      row.setAttribute("aria-current", "true");
      row.scrollIntoView({{ block: "nearest", behavior: "smooth" }});
      statusLabel.textContent = `${{event.chord}} · ${{event.message}}`;

      event.notes.forEach(note => {{
        const oscillator = audioContext.createOscillator();
        const gain = audioContext.createGain();
        oscillator.type = "triangle";
        oscillator.frequency.value = 440 * Math.pow(2, (note - 69) / 12);
        gain.gain.setValueAtTime(0.0001, start);
        gain.gain.linearRampToValueAtTime(0.09, start + 0.025);
        gain.gain.exponentialRampToValueAtTime(0.0001, start + duration * 0.92);
        oscillator.connect(gain);
        gain.connect(audioContext.destination);
        oscillator.start(start);
        oscillator.stop(start + duration);
        sources.push(oscillator);
        oscillator.onended = () => {{
          sources = sources.filter(source => source !== oscillator);
          oscillator.disconnect();
          gain.disconnect();
        }};
      }});
      timer = window.setTimeout(
        () => playEvent(index + 1, activePlayback),
        duration * 1000
      );
    }}

    playButton.addEventListener("click", async () => {{
      if (isPlaying) {{
        stopPlayback();
        return;
      }}
      if (!audioContext || audioContext.state === "closed") {{
        audioContext = new AudioContext();
      }}
      await audioContext.resume();
      stopPlayback("Tocando a sinfonia...");
      isPlaying = true;
      playButton.innerHTML = '<span aria-hidden="true">■</span><span>Stop</span>';
      playButton.setAttribute("aria-label", "Parar sinfonia");
      const activePlayback = playbackId;
      playEvent(0, activePlayback);
    }});
  </script>
</body>
</html>
"""


def write_site(events, html_path, svg_path, repository_url="", tempo=120, midi_path=""):
    html_path = Path(html_path)
    svg_path = Path(svg_path)
    html_path.parent.mkdir(parents=True, exist_ok=True)
    svg_path.parent.mkdir(parents=True, exist_ok=True)
    svg_path.write_text(
        render_score_svg(events, repository_url),
        encoding="utf-8",
    )
    midi_href = Path(midi_path).name if midi_path else ""
    if not midi_href:
        midi_href = "git_symphony.mid"
    html_path.write_text(
        render_player_html(
            events,
            svg_path.name,
            midi_href,
            repository_url,
            tempo,
        ),
        encoding="utf-8",
    )
