import sys

from .cli import main


def run() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    sys.exit(main())


if __name__ == "__main__":
    run()
