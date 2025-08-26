# dnswatch/cli.py
import argparse
from dnswatch.runner import once, run_loop

def main():
    p = argparse.ArgumentParser(prog="dnswatch")
    sub = p.add_subparsers(dest="cmd", required=True)

    s_once = sub.add_parser("once", help="Run a single collection + VT pass")
    s_once.set_defaults(fn=lambda args: once())

    s_run = sub.add_parser("run", help="Run continuously")
    s_run.add_argument("--interval", type=int, default=300, help="Seconds between passes")
    s_run.set_defaults(fn=lambda args: run_loop(args.interval))

    s_loop = sub.add_parser("loop", help="Alias for 'run'")
    s_loop.add_argument("--interval", type=int, default=300)
    s_loop.set_defaults(fn=lambda args: run_loop(args.interval))

    args = p.parse_args()
    args.fn(args)

if __name__ == "__main__":
    main()
