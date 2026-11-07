#!/usr/bin/env python3
"""Start the NextGen Risk Register.

    python run.py            # start on http://127.0.0.1:8000 (seeds demo data on first run)
    python run.py --reseed   # wipe the database and rebuild the demo dataset
    python run.py --empty    # start with an empty register (no demo data)
"""
import argparse
import sys

import uvicorn

from backend import seed as seeder
from backend.db import init_db


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--reseed", action="store_true", help="wipe and rebuild demo data")
    ap.add_argument("--empty", action="store_true", help="do not load demo data")
    ap.add_argument("--reload", action="store_true", help="auto-reload for development")
    args = ap.parse_args()

    if args.reseed:
        seeder.reset()
        seeder.seed()
        print("Demo data rebuilt.")
    else:
        init_db()
        if not args.empty and seeder.is_empty():
            seeder.seed()
            print("Loaded demo data (Lumen Analytics).")

    print(f"NextGen Risk Register -> http://{args.host}:{args.port}  (API docs at /docs)")
    uvicorn.run("backend.main:app", host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    sys.exit(main())
