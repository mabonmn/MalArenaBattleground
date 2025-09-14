import argparse
from test import informational, measure_efficacy, MAXFILESIZE, TIMEOUT, TINYIMPORT, get_raw_result
import json
import pathlib
import requests


def main():
    parser = argparse.ArgumentParser(
        description="Test defense ML docker image", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument(
        '-m', required=True, type=str, help='folder or archize (ZIP or TAR.GZ or TAR.BZ2) containing malicious samples')
    parser.add_argument(
        '-b', required=True, type=str, help='folder or archive (ZIP or TAR.GZ or TAR.BZ2) containing benign samples')
    parser.add_argument('--url', type=str, default='http://127.0.0.1:8080/',
                        help='URL address of ML detection service')
    parser.add_argument('--max', type=int, default=MAXFILESIZE,
                        help="maximum file size to read from folder/archive")
    parser.add_argument('--stopafter', type=int, default=5000,
                        help="test up to this many files in each folder/archive")
    parser.add_argument('--timeout', type=int,
                        default=TIMEOUT, help="timeout for requests")
    parser.add_argument('--out-dir', type=str, default=None,
                        help='Directory to write fps.txt, fns.txt, errors.txt (default: directory of --benign path)')
    args = parser.parse_args()

    assert pathlib.Path(args.b).is_file() or pathlib.Path(
        args.b).is_dir(), "benign samples path does not exist"
    assert pathlib.Path(args.m).is_file() or pathlib.Path(
        args.m).is_dir(), "malicious samples path does not exist"

    # check the format of responses
    try:
        res = get_raw_result(TINYIMPORT, args.url, args.timeout)
        json_result = res.json()
    except requests.RequestException:
        print(f'Error calling service at {args.url}')
        return
    except json.decoder.JSONDecodeError:
        print(f'Expected json response, but received "{res.text}"')
        return

    assert 'result' in json_result, f'Expected JSON with "result" key, but received {json.dumps(json_result)}'

    # check that the response is an integer
    assert isinstance(json_result['result'], int), f'Expected an integer response but received {json.dumps(json_result)}'

    # provide information on some benign corner cases
    print(informational(args.url, args.timeout))

    # efficacy test: malicious files are tested first, which helps measure FP rate for stateful defenses
    summary, fps, fns, errors = measure_efficacy(
        args.b, args.m, args.url, args.max, args.timeout, stop_after=args.stopafter)

    # Determine output directory: --out-dir, else the directory of the benign path
    if args.out_dir is not None:
        out_dir = pathlib.Path(args.out_dir)
    else:
        bpath = pathlib.Path(args.b)
        out_dir = bpath if bpath.is_dir() else bpath.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    fps_path = out_dir / 'fps.txt'
    fns_path = out_dir / 'fns.txt'
    errs_path = out_dir / 'errors.txt'
    summary_path = out_dir / 'summary.json'

    with open(fps_path, 'w') as outfile:
        for fp in fps:
            outfile.write(f'{fp}\n')

    with open(fns_path, 'w') as outfile:
        for fn in fns:
            outfile.write(f'{fn}\n')

    with open(errs_path, 'w') as outfile:
        for fn, e in errors:
            outfile.write(f'{fn}\t{e}\n')

    # Save summary as JSON in the same directory for convenience
    try:
        with open(summary_path, 'w') as fsum:
            json.dump(summary, fsum, indent=2)
    except Exception:
        pass

    print('Summary:')
    print(json.dumps(summary, indent=2))
    print(f"Saved outputs to: {out_dir}\n  - {fps_path}\n  - {fns_path}\n  - {errs_path}\n  - {summary_path}")


if __name__ == '__main__':
    main()
