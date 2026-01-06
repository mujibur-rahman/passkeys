import time
import statistics
import requests

BASE = "http://localhost:8000"

def percentile(sorted_vals, p):
    k = (len(sorted_vals) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)

def measure(username: str, n=400, warmup=20, timeout=5.0):
    s = requests.Session()

    # warmup to reduce connection/setup noise
    for _ in range(warmup):
        try:
            s.post(f"{BASE}/api/login/options", json={"username": username}, timeout=timeout)
        except Exception:
            pass

    times = []
    codes = []
    for _ in range(n):
        t0 = time.perf_counter()
        try:
            r = s.post(f"{BASE}/api/login/options", json={"username": username}, timeout=timeout)
            codes.append(r.status_code)
            _ = r.text
        except Exception:
            codes.append(-1)
        times.append(time.perf_counter() - t0)

    times_sorted = sorted(times)
    return times, times_sorted, codes

def summarize(label, times, times_sorted, codes):
    mean = statistics.mean(times)
    median = statistics.median(times)
    stdev = statistics.pstdev(times)
    p90 = percentile(times_sorted, 90)
    p95 = percentile(times_sorted, 95)
    p99 = percentile(times_sorted, 99)

    print(f"\n=== {label} ===")
    print(f"count={len(times)}")
    print(f"mean={mean*1000:.2f}ms  median={median*1000:.2f}ms  stdev={stdev*1000:.2f}ms")
    print(f"p90={p90*1000:.2f}ms  p95={p95*1000:.2f}ms  p99={p99*1000:.2f}ms")
    print(f"status_codes={sorted(set(codes))}  errors={sum(1 for c in codes if c == -1)}")

known, known_s, known_codes = measure("mujibur", n=500)
unknown, unknown_s, unknown_codes = measure("nonexistent_user_123456", n=500)

summarize("KNOWN", known, known_s, known_codes)
summarize("UNKNOWN", unknown, unknown_s, unknown_codes)

print("\n=== Difference (KNOWN - UNKNOWN) ===")
print(f"mean_diff={(statistics.mean(known) - statistics.mean(unknown))*1000:.2f}ms")
print(f"median_diff={(statistics.median(known) - statistics.median(unknown))*1000:.2f}ms")