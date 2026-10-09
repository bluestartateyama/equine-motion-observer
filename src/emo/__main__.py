import argparse
from .ui import launch

def main():
    parser = argparse.ArgumentParser(description='Local equine visual observation notebook')
    parser.add_argument('--enable-siwc', action='store_true',
        help='Enable future explicitly authorized OAuth/network operations; default is offline')
    args = parser.parse_args()
    launch(live=args.enable_siwc)

if __name__ == '__main__':
    main()
