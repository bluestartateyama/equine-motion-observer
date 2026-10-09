"""Generate owned geometric fixtures, with no real media or inference."""
import json
import sys
from pathlib import Path
from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from emo.images import LocalImage
from emo.observation import empty_observation, make_record

def create():
    images = ROOT / 'examples/synthetic_images'
    results = ROOT / 'examples/example_results'
    images.mkdir(parents=True, exist_ok=True)
    results.mkdir(parents=True, exist_ok=True)
    image = Image.new('RGB', (720, 480), '#e9eff2')
    draw = ImageDraw.Draw(image)
    draw.rectangle((40, 380, 680, 410), fill='#899ea6')
    draw.ellipse((210, 180, 510, 320), fill='#496d76')
    draw.polygon([(480, 230), (510, 100), (610, 120), (600, 210)], fill='#496d76')
    draw.line((260, 290, 240, 380), fill='#31474d', width=22)
    draw.line((440, 290, 470, 380), fill='#31474d', width=22)
    draw.line((220, 230, 150, 280), fill='#31474d', width=12)
    for number, fmt in enumerate(('PNG', 'JPEG'), 1):
        extension = 'png' if fmt == 'PNG' else 'jpg'
        path = images / ('synthetic_geometry.' + extension)
        image.save(path, fmt, **({'quality': 92} if fmt == 'JPEG' else {}))
        source = LocalImage.load(path, 'synthetic-frame-1')
        observation = empty_observation('synthetic-subject')
        for feature in observation['features'].values():
            feature['reason'] = 'Geometric illustration; no real equine observation is possible.'
        record = make_record(observation, source, 'synthetic')
        record['result_id'] = f'00000000-0000-4000-8000-{number:012d}'
        record['timestamp'] = '2026-01-01T00:00:00+00:00'
        (results / ('synthetic_' + extension + '.json')).write_text(
            json.dumps(record, ensure_ascii=False, indent=2), 'utf-8')

if __name__ == '__main__':
    create()
