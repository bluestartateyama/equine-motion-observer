"""Launch from a source checkout without installing a package."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent / 'src'))
from emo.__main__ import main

if __name__ == '__main__':
    main()
