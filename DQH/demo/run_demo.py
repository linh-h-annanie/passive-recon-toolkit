"""Run both modes sequentially; stop the entire demonstration on any error."""
import argparse
import json
import random
import time

from recon import BASE, now, run_recon


def main():
    parser = argparse.ArgumentParser(description='Chạy demo Người 3 trên domain đã được phép.')
    parser.add_argument('--domain', required=True)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    summary = {'domain': args.domain, 'dry_run': args.dry_run, 'started_at': now(), 'runs': []}
    try:
        for mode in ['dorks', 'search']:
            if summary['runs']:
                if summary['runs'][-1]['status'] == 'error':
                    summary['skipped_mode'] = mode
                    break
                if not args.dry_run:
                    time.sleep(random.uniform(10, 15))
            report = run_recon(args.domain, mode=mode, dry_run=args.dry_run)
            summary['runs'].append({'mode': mode, 'status': report['status'],
                                    'output_file': report['output_file']})
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    summary['completed_at'] = now()
    summary['status'] = 'error' if any(r['status'] == 'error' for r in summary['runs']) else (
        'dry_run' if args.dry_run else 'completed')
    target = BASE / 'output' / ('dry_run_summary.json' if args.dry_run else 'live_run_summary.json')
    target.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=True, indent=2))
    return 1 if summary['status'] == 'error' else 0


if __name__ == '__main__':
    raise SystemExit(main())
