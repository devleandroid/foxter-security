#!/usr/bin/env python3
"""
Git Symphony Generator - Transforma commits do Git em música
Autor: LeBronx
Data: 2026-10-13
"""

import argparse
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from midiutil import MIDIFile

from scripts.git_symphony_site import write_site


MAJOR_SCALE = [0, 2, 4, 5, 7, 9, 11]
CHORD_NAMES = ["C", "Dm", "Em", "F", "G", "Am", "Bdim"]


class GitSymphony:
    def __init__(self, repo_path=".", tempo=120):
        self.repo_path = repo_path
        self.tempo = tempo
        self.events = []

    def get_git_commits(self, max_commits=50):
        """Obtém commits do repositório git"""
        try:
            result = subprocess.run(
                [
                    "git",
                    "log",
                    "--reverse",
                    "--pretty=format:%H%x1f%an%x1f%ai%x1f%s",
                    f"-n{max_commits}",
                ],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True
            )

            commits = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split('\x1f', 3)
                    if len(parts) >= 4:
                        commits.append({
                            'hash': parts[0],
                            'author': parts[1],
                            'date': parts[2],
                            'message': parts[3]
                        })
            return commits
        except subprocess.CalledProcessError as error:
            raise RuntimeError(
                f"Não foi possível ler o histórico Git em {self.repo_path!r}."
            ) from error

    def hash_to_midi_note(self, commit_hash):
        """
        Converte hash do commit para nota MIDI (0-127)
        Usa escala maior de C para soar harmônico
        """
        hash_value = int(commit_hash[:8], 16)

        octave = 60 + (hash_value % 3) * 12
        note_in_scale = hash_value % len(MAJOR_SCALE)
        return octave + MAJOR_SCALE[note_in_scale]

    def commit_to_chord(self, commit_hash):
        """Mapeia o hash para uma tríade diatônica em Dó maior."""
        hash_value = int(commit_hash[:8], 16)
        degree = hash_value % len(MAJOR_SCALE)
        octave = 60 + (hash_value % 3) * 12
        notes = [
            octave + MAJOR_SCALE[(degree + interval) % len(MAJOR_SCALE)]
            + ((degree + interval) // len(MAJOR_SCALE)) * 12
            for interval in (0, 2, 4)
        ]
        return CHORD_NAMES[degree], notes

    def message_to_velocity(self, message):
        """
        Determina intensidade da nota baseado no tipo de commit
        feat = 100 (forte), fix = 80 (médio), docs = 60 (suave)
        """
        message_lower = message.lower()

        if 'feat' in message_lower or 'feature' in message_lower:
            return 100
        elif 'fix' in message_lower or 'bugfix' in message_lower:
            return 85
        elif 'refactor' in message_lower:
            return 90
        elif 'docs' in message_lower or 'documentation' in message_lower:
            return 60
        elif 'test' in message_lower:
            return 75
        elif 'chore' in message_lower:
            return 70
        else:
            return 80

    def calculate_duration(self, date_str, prev_date_str):
        """
        Calcula duração da nota baseado no tempo entre commits
        Commits rápidos = notas curtas, commits lentos = notas longas
        """
        if not prev_date_str:
            return 1.0

        try:
            date = datetime.strptime(date_str[:19], '%Y-%m-%d %H:%M:%S')
            prev_date = datetime.strptime(prev_date_str[:19], '%Y-%m-%d %H:%M:%S')

            hours_diff = abs((date - prev_date).total_seconds()) / 3600

            if hours_diff < 2:
                return 0.5
            elif hours_diff < 8:
                return 1.0
            elif hours_diff < 24:
                return 1.5
            else:
                return 2.0
        except ValueError:
            return 1.0

    def generate_symphony(self, output_file="git_symphony.mid"):
        """Gera a sinfonia completa a partir dos commits"""
        commits = self.get_git_commits()

        if not commits:
            raise RuntimeError(f"Nenhum commit encontrado em {self.repo_path!r}.")

        midi = MIDIFile(1)
        track = 0
        channel = 0
        midi.addTempo(track, 0, self.tempo)

        print(f"🎵 Gerando sinfonia com {len(commits)} commits...\n")

        prev_date = None
        events = []
        current_time = 0

        print(f"{'#':<4} {'Cifra':<6} {'Vel':<5} {'Dur':<5} {'Mensagem do Commit'}")
        print("-" * 70)

        for i, commit in enumerate(commits, 1):
            chord, notes = self.commit_to_chord(commit['hash'])
            velocity = self.message_to_velocity(commit['message'])
            duration = self.calculate_duration(commit['date'], prev_date)

            for note in notes:
                midi.addNote(track, channel, note, current_time, duration, velocity)

            msg = commit['message'][:45]

            print(f"{i:<4} {chord:<6} {velocity:<5} {duration:<5.1f} {msg}")
            events.append({
                **commit,
                "chord": chord,
                "notes": notes,
                "velocity": velocity,
                "duration": duration,
                "time": current_time,
            })
            current_time += duration
            prev_date = commit['date']

        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "wb") as output_file_handle:
            midi.writeFile(output_file_handle)

        self.events = events
        print("\n" + "=" * 70)
        print(f"✅ Sinfonia gerada: {output_file}")
        print(f"📊 Total de acordes: {len(commits)}")
        print(
            f"⏱️  Duração total: {current_time:.1f} beats "
            f"({current_time / self.tempo * 60:.1f} segundos)"
        )
        print("=" * 70)

        return output_file


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Gera MIDI, partitura em piano e player web a partir do Git."
    )
    parser.add_argument("repo_path", nargs="?", default=".", help="caminho do repositório")
    parser.add_argument("--midi", default="git_symphony.mid", help="arquivo MIDI de saída")
    parser.add_argument("--html", help="gera uma página interativa HTML")
    parser.add_argument("--svg", help="gera uma imagem SVG da partitura")
    parser.add_argument(
        "--repository-url",
        default="",
        help="URL do repositório GitHub para links dos commits",
    )
    args = parser.parse_args(argv)

    try:
        symphony = GitSymphony(repo_path=args.repo_path)
        midi_path = symphony.generate_symphony(args.midi)
        if args.html or args.svg:
            html_path = args.html or "git_symphony.html"
            svg_path = args.svg or "git_symphony.svg"
            write_site(
                symphony.events,
                html_path,
                svg_path,
                args.repository_url,
                symphony.tempo,
                midi_path,
            )
            print(f"🌐 Player interativo: {html_path}")
            print(f"🎹 Partitura SVG: {svg_path}")
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Erro: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
