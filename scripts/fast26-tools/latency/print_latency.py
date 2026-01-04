#!/usr/bin/env python3
import argparse
import os
import re
import json
import math

parser = argparse.ArgumentParser(description="'stress' range average calculator", add_help=False)
parser.add_argument("start_id", type=int, help="start id (e.g., 8168)")
parser.add_argument("end_id", type=int, help="end id (e.g., 8295)")
parser.add_argument("-D", "--dir", default=".", help="directory containing log files")
parser.add_argument("--prefix", default="stress_mem_access_latency_", help="file prefix")
parser.add_argument("--suffix", default=".log", help="file suffix")

parser.add_argument("-h", "--human-readable", action="store_true", help="print memory/latency in human readable units")
parser.add_argument("-d", "--delete_zero", action="store_true", help="계산시 0은 제외 (latency=0 또는 access=0이면 제외)")
parser.add_argument("-z", "--wjftkvudrbs", action="store_true", help="절사 평균 (row-weighted에만 적용: 양끝 2개 제거)")
parser.add_argument("--help", required=False, action="store_true", help="display this help and exit")

LINE_NO_RE = re.compile(r"^\s*\d+\s+")  # vim에서 복사한 줄번호 제거


def byte_transform(val, bsize=1000):
    to = ["bytes", "KB", "MB", "GB", "TB", "PB"]
    cnt = 0
    val = float(val)
    while val >= bsize and cnt < len(to) - 1:
        val /= bsize
        cnt += 1
    return str(round(val, 2)) + " " + to[cnt]


def latency_transform_ns(ns_val, bsize=1000):
    # ns -> us -> ms -> s
    to = ["ns", "us", "ms", "s"]
    cnt = 0
    val = float(ns_val)
    while val >= bsize and cnt < len(to) - 1:
        val /= bsize
        cnt += 1
    return str(round(val, 2)) + " " + to[cnt]


def is_data_line(line: str) -> bool:
    s = LINE_NO_RE.sub("", line).strip()
    if not s:
        return False
    if s.lower().startswith("elapsed_time"):
        return False
    if s.startswith("~") or s.startswith('"'):
        return False
    # 첫 토큰이 숫자면 데이터로 간주
    first = s.split(",", 1)[0].strip()
    try:
        float(first)
        return True
    except ValueError:
        return False


def parse_rows(path: str):
    """
    Returns list of rows: (elapsed_time_s, mem_bytes, access_count, avg_latency_ns)
    """
    rows = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.rstrip("\n")
            s = LINE_NO_RE.sub("", line).strip()
            if not s:
                continue
            if not is_data_line(s):
                continue

            parts = [p.strip() for p in s.split(",")]
            if len(parts) < 4:
                continue

            try:
                t = float(parts[0])
                mem = float(parts[1])
                acc = float(parts[2])
                lat = float(parts[3])
            except ValueError:
                continue

            rows.append((t, mem, acc, lat))
    return rows


def mean(vals):
    return sum(vals) / len(vals) if vals else float("nan")


def trimmed_mean(vals, cut_cnt=2):
    if not vals:
        return float("nan")
    v = sorted(vals)
    if len(v) <= 2 * cut_cnt:
        return mean(v)
    v = v[cut_cnt: len(v) - cut_cnt]
    return mean(v)


def main():
    args = parser.parse_args()
    if args.help:
        parser.print_help()
        return

    if args.end_id < args.start_id:
        print(json.dumps({"error": "end_id must be >= start_id"}, indent=2, ensure_ascii=False))
        return

    found = 0
    missing = []
    total_rows = 0

    mem_list = []
    acc_list = []
    lat_list = []

    # access-weighted latency
    lat_x_acc_sum = 0.0
    acc_sum_for_latency = 0.0

    for i in range(args.start_id, args.end_id + 1):
        fname = f"{args.prefix}{i}{args.suffix}"
        fpath = os.path.join(args.dir, fname)
        if not os.path.isfile(fpath):
            missing.append(fname)
            continue

        found += 1
        rows = parse_rows(fpath)
        total_rows += len(rows)

        for (_t, mem, acc, lat) in rows:
            # delete_zero 정책: latency=0 또는 acc=0이면 latency 통계에서 제외
            if args.delete_zero and (lat == 0 or acc == 0):
                # mem/acc의 row-weighted 평균도 제외하고 싶으면 여기서 continue로 바꾸면 됨
                # 지금은 "latency=0/acc=0만 latency 통계에서 제외"로 처리
                mem_list.append(mem)
                acc_list.append(acc)
                continue

            mem_list.append(mem)
            acc_list.append(acc)
            lat_list.append(lat)

            # access-weighted latency는 access가 0이면 의미없어서 제외
            if acc > 0:
                lat_x_acc_sum += lat * acc
                acc_sum_for_latency += acc

    if found == 0:
        out = {
            "error": "no log files found in the given range",
            "range": {"start_id": args.start_id, "end_id": args.end_id},
            "dir": os.path.abspath(args.dir),
            "missing_preview": missing[:10],
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return

    # row-weighted averages
    avg_mem = mean(mem_list)
    avg_acc = mean(acc_list)

    if args.wjftkvudrbs:
        avg_lat_row = trimmed_mean(lat_list, cut_cnt=2)
    else:
        avg_lat_row = mean(lat_list)

    # access-weighted latency (추천)
    avg_lat_access = (lat_x_acc_sum / acc_sum_for_latency) if acc_sum_for_latency > 0 else float("nan")

    def fmt_mem(x):
        return byte_transform(x) if args.human_readable and not math.isnan(x) else (x if not math.isnan(x) else "NaN")

    def fmt_lat(x):
        return latency_transform_ns(x) if args.human_readable and not math.isnan(x) else (x if not math.isnan(x) else "NaN")

    out = {
        "range": {"start_id": args.start_id, "end_id": args.end_id},
        "dir": os.path.abspath(args.dir),
        "pattern": f"{args.prefix}<ID>{args.suffix}",
        "options": {
            "human_readable": args.human_readable,
            "delete_zero": args.delete_zero,
            "trimmed_mean_row_weighted": args.wjftkvudrbs,
        },
        "files": {
            "found": found,
            "missing": len(missing),
            "missing_preview": missing[:10],
        },
        "rows": {
            "total_rows_sum_over_files": total_rows,
            "latency_rows_used": len(lat_list),
        },
        "avg": {
            "memory_usage_bytes_row_weighted": fmt_mem(avg_mem),
            "access_count_row_weighted": round(avg_acc, 4) if not math.isnan(avg_acc) else "NaN",
            "avg_latency_ns_row_weighted": fmt_lat(avg_lat_row),
            "avg_latency_ns_access_weighted": fmt_lat(avg_lat_access),
        },
    }

    print(json.dumps(out, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

