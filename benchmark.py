import argparse
import asyncio
import json
import os
import time
from datetime import datetime, UTC
from pathlib import Path

import httpx


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Wegis benchmark runner")
    parser.add_argument(
        "--mode",
        choices=["baseline", "optimized"],
        required=True,
        help="Benchmark scenario label used in output filenames and reports",
    )
    parser.add_argument(
        "--base-url",
        default="http://localhost:8000",
        help="Server base URL",
    )
    parser.add_argument(
        "--urls-file",
        default="",
        help="Path to JSON file containing URL list",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=2,
        help="Warm-up request count",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=4,
        help="Concurrent request count",
    )
    parser.add_argument(
        "--output-dir",
        default="./log/benchmarks",
        help="Directory where benchmark results are saved",
    )
    return parser.parse_args()


def load_urls(urls_file: str) -> list[str]:
    if urls_file:
        with open(urls_file, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        if not isinstance(loaded, list):
            raise ValueError("URLs file must contain a JSON list")
        return [str(item) for item in loaded]

    return [
        "https://google.com",
        "https://github.com",
        "https://example.com",
        "https://stackoverflow.com",
        "https://python.org",
    ]


async def run_single(
    client: httpx.AsyncClient,
    base_url: str,
    url: str,
) -> dict:
    started = time.perf_counter()
    resp = await client.post(
        f"{base_url}/analyze/check",
        json={"url": url},
    )
    elapsed_ms = (time.perf_counter() - started) * 1000

    payload = {
        "request_url": url,
        "status_code": resp.status_code,
        "latency_ms": round(elapsed_ms, 3),
    }

    try:
        payload["response"] = resp.json()
    except Exception:
        payload["response"] = {"raw": resp.text}

    return payload


async def run_benchmark(
    base_url: str,
    mode: str,
    urls: list[str],
    warmup: int,
    concurrency: int,
) -> list[dict]:
    timeout = httpx.Timeout(60.0)
    sem = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(timeout=timeout) as client:
        await client.delete(f"{base_url}/analyze/perf/records")

        for i in range(min(warmup, len(urls))):
            await run_single(client, base_url, urls[i])

        async def guarded(u: str) -> dict:
            async with sem:
                return await run_single(client, base_url, u)

        results = await asyncio.gather(*[guarded(u) for u in urls])
        return results


def summarize(results: list[dict]) -> dict:
    latencies = [r["latency_ms"] for r in results if r.get("status_code") == 200]
    if not latencies:
        return {
            "count": len(results),
            "ok": 0,
            "avg_ms": 0,
            "p95_ms": 0,
            "max_ms": 0,
        }

    ordered = sorted(latencies)
    p95_index = max(0, int(len(ordered) * 0.95) - 1)

    return {
        "count": len(results),
        "ok": len(latencies),
        "avg_ms": round(sum(latencies) / len(latencies), 3),
        "p95_ms": round(ordered[p95_index], 3),
        "max_ms": round(max(latencies), 3),
    }


async def fetch_perf_records(base_url: str) -> list[dict]:
    timeout = httpx.Timeout(30.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.get(f"{base_url}/analyze/perf/records")
        response.raise_for_status()
        payload = response.json()
        records = payload.get("data", [])
        if isinstance(records, list):
            return records
        return []


def main() -> None:
    args = parse_args()
    urls = load_urls(args.urls_file)

    started_at = datetime.now(UTC).isoformat()
    results = asyncio.run(
        run_benchmark(
            base_url=args.base_url,
            mode=args.mode,
            urls=urls,
            warmup=args.warmup,
            concurrency=args.concurrency,
        )
    )

    summary = summarize(results)
    metrics = asyncio.run(fetch_perf_records(args.base_url))

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    payload = {
        "timestamp": started_at,
        "mode": args.mode,
        "scenario": {
            "base_url": args.base_url,
            "url_count": len(urls),
            "warmup": args.warmup,
            "concurrency": args.concurrency,
        },
        "summary": summary,
        "results": metrics,
        "raw_results": results,
    }

    output_file = output_dir / f"{args.mode}_results.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    print(f"Saved benchmark output: {os.fspath(output_file)}")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
