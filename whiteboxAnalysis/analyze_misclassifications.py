#!/usr/bin/env python3
"""
Analyze misclassified samples by joining evaluation results with extracted features.

Outputs human-readable CSVs and a concise Markdown report to understand:
- Which files were misclassified (FP/FN) and their key feature values
- How FP differ from correctly-classified goodware (TN)
- How FN differ from correctly-classified malware (TP)

Data dependencies:
- challenge_evaluation_results.csv (at repo root)
- whiteboxAnalysis/challenge_features/{challenge_features.npy, challenge_labels.npy, challenge_paths.txt}

Artifacts written to:
- whiteboxAnalysis/misclassification_analysis/
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd


def find_features_dir(start: Path) -> Path:
    """Locate the challenge_features directory produced by extraction.

    Tries common locations relative to the repository root.
    """
    candidates = [
        start / "whiteboxAnalysis" / "challenge_features",
        start / "challenge_features",
    ]
    for c in candidates:
        if (c / "challenge_features.npy").exists() and (c / "challenge_paths.txt").exists():
            return c
    # Fallback to absolute path used by earlier scripts, if present
    abs_fallback = Path("/home/benchodbaap/DataAna/whiteboxAnalysis/challenge_features")
    if (abs_fallback / "challenge_features.npy").exists():
        return abs_fallback
    raise FileNotFoundError(
        "Could not find challenge_features directory; expected at whiteboxAnalysis/challenge_features/"
    )


def normalize_to_rel(path: str, root_token: str = "challenge_ds") -> str:
    """Normalize a file path to a relative suffix starting at root_token.

    Examples:
      "/abs/.../challenge_ds/goodware/1/1" -> "challenge_ds/goodware/1/1"
      "challenge_ds/goodware/1/1" -> "challenge_ds/goodware/1/1"
    """
    parts = Path(path).parts
    if root_token in parts:
        idx = parts.index(root_token)
        return str(Path(*parts[idx:]))
    return path.replace("./", "").lstrip("/")


def zscore(arr: np.ndarray, mean: np.ndarray, std: np.ndarray, eps: float = 1e-9) -> np.ndarray:
    return (arr - mean) / (std + eps)


def topk_indices(values: np.ndarray, k: int) -> np.ndarray:
    k = min(k, values.size)
    if k <= 0:
        return np.array([], dtype=int)
    return np.argpartition(-values, k - 1)[:k]


def analyze_misclassifications(repo_root: Path) -> Dict[str, Path]:
    # Locate inputs
    eval_path = repo_root / "challenge_evaluation_results.csv"
    features_dir = find_features_dir(repo_root)

    out_dir = repo_root / "whiteboxAnalysis" / "misclassification_analysis"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Load evaluation results
    eval_df = pd.read_csv(eval_path)
    # Expect columns: file_path, expected, predicted, correct
    if not {"file_path", "expected", "predicted", "correct"}.issubset(eval_df.columns):
        raise ValueError(
            "challenge_evaluation_results.csv must contain columns: file_path, expected, predicted, correct"
        )

    eval_df["rel_path"] = eval_df["file_path"].apply(lambda p: normalize_to_rel(str(p)))

    # Load features
    X = np.load(features_dir / "challenge_features.npy")
    y = np.load(features_dir / "challenge_labels.npy")
    with open(features_dir / "challenge_paths.txt", "r") as f:
        feat_paths = [line.strip() for line in f]

    feat_rel = [normalize_to_rel(p) for p in feat_paths]
    feat_df = pd.DataFrame({
        "rel_path": feat_rel,
        "abs_path": feat_paths,
        "label": y,
        "idx": np.arange(len(feat_paths)),
    })

    # Join evaluation with features by relative path
    merged = eval_df.merge(feat_df, on="rel_path", how="left", validate="one_to_one")
    missing = merged[merged["idx"].isna()]
    if not missing.empty:
        # Some paths in eval file not found in features; warn but continue
        miss_list = missing[["file_path"]].head(10).to_dict(orient="records")
        print(f"Warning: {len(missing)} eval rows could not be matched to features. Showing first 10: {miss_list}")
    merged = merged.dropna(subset=["idx"]).copy()
    merged["idx"] = merged["idx"].astype(int)

    # Split groups
    is_tp = (merged["expected"] == 1) & (merged["predicted"] == 1)
    is_tn = (merged["expected"] == 0) & (merged["predicted"] == 0)
    is_fp = (merged["expected"] == 0) & (merged["predicted"] == 1)
    is_fn = (merged["expected"] == 1) & (merged["predicted"] == 0)

    idx_tp = merged.loc[is_tp, "idx"].to_numpy(dtype=int)
    idx_tn = merged.loc[is_tn, "idx"].to_numpy(dtype=int)
    idx_fp = merged.loc[is_fp, "idx"].to_numpy(dtype=int)
    idx_fn = merged.loc[is_fn, "idx"].to_numpy(dtype=int)

    # Basic stats
    stats = {
        "TP": int(is_tp.sum()),
        "TN": int(is_tn.sum()),
        "FP": int(is_fp.sum()),
        "FN": int(is_fn.sum()),
        "Total": int(len(merged)),
    }

    # Identify zero-feature rows (failed extraction)
    zero_mask = np.all(X == 0, axis=1)
    merged["zero_features"] = merged["idx"].map(lambda i: bool(zero_mask[i]))

    # For legibility include first 10 features; feature_0 ~ size, feature_1 ~ entropy
    def pick_feats(arr_indices: np.ndarray, k_preview: int = 10) -> pd.DataFrame:
        if arr_indices.size == 0:
            return pd.DataFrame()
        subset = X[arr_indices, :]
        cols = {f"feature_{i}": subset[:, i] for i in range(min(k_preview, X.shape[1]))}
        return pd.DataFrame(cols)

    miscls_df = merged.loc[is_fp | is_fn, [
        "rel_path", "file_path", "abs_path", "expected", "predicted", "correct", "zero_features", "idx"
    ]].copy()

    # Attach preview features
    prev_feats = pick_feats(miscls_df["idx"].to_numpy())
    miscls_out = pd.concat([miscls_df.reset_index(drop=True), prev_feats.reset_index(drop=True)], axis=1)
    miscls_csv = out_dir / "misclassified_samples_preview.csv"
    miscls_out.to_csv(miscls_csv, index=False)

    # Compute group means and deltas
    def group_stats(idxs: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        if idxs.size == 0:
            return np.zeros(X.shape[1], dtype=float), np.ones(X.shape[1], dtype=float)
        G = X[idxs]
        # Exclude zero-feature rows when computing stats
        G = G[~np.all(G == 0, axis=1)]
        if G.size == 0:
            return np.zeros(X.shape[1], dtype=float), np.ones(X.shape[1], dtype=float)
        mean = G.mean(axis=0)
        std = G.std(axis=0)
        # Avoid zero std for z-scores downstream
        std[std == 0] = 1.0
        return mean, std

    mean_tn, std_tn = group_stats(idx_tn)
    mean_tp, std_tp = group_stats(idx_tp)
    mean_fp, _ = group_stats(idx_fp)
    mean_fn, _ = group_stats(idx_fn)

    # Deltas for interpretation
    # FP vs TN (goodware predicted as malware vs correctly predicted goodware)
    delta_fp_vs_tn = mean_fp - mean_tn
    # FN vs TP (malware predicted as goodware vs correctly predicted malware)
    delta_fn_vs_tp = mean_fn - mean_tp

    def write_top_deltas(delta: np.ndarray, label: str, k: int = 30) -> Path:
        abs_vals = np.abs(delta)
        top_idx = topk_indices(abs_vals, k)
        df = pd.DataFrame({
            "feature": [int(i) for i in top_idx],
            "delta": delta[top_idx],
            "abs_delta": abs_vals[top_idx],
        }).sort_values("abs_delta", ascending=False)
        # Provide friendly names for first few known features
        def fname(i: int) -> str:
            if i == 0:
                return "file_size_bytes"
            if i == 1:
                return "byte_entropy"
            return f"feature_{i}"
        df.insert(1, "feature_name", [fname(int(i)) for i in df["feature"]])
        outp = out_dir / f"top_feature_deltas_{label}.csv"
        df.to_csv(outp, index=False)
        return outp

    out_fp_delta = write_top_deltas(delta_fp_vs_tn, "fp_vs_tn")
    out_fn_delta = write_top_deltas(delta_fn_vs_tp, "fn_vs_tp")

    # Per-sample deviation summary for misclassified files
    # Compare to their true-class correct centroid (FP -> TN centroid, FN -> TP centroid)
    def per_sample_summary(row: pd.Series) -> Dict[str, object]:
        idx = int(row["idx"])
        x = X[idx]
        if row["expected"] == 0:  # goodware misclassified => compare to TN
            mean_ref, std_ref = mean_tn, std_tn
            ref_name = "TN"
        else:  # malware misclassified => compare to TP
            mean_ref, std_ref = mean_tp, std_tp
            ref_name = "TP"
        zs = zscore(x, mean_ref, std_ref)
        # Zero-feature vectors are special
        if np.all(x == 0):
            top_feats = "<all-zero features>"
            l2 = float(np.linalg.norm(zs))
        else:
            contrib = np.abs(zs)
            top_idx = topk_indices(contrib, 5)
            def fname(i: int) -> str:
                if i == 0:
                    return "file_size_bytes"
                if i == 1:
                    return "byte_entropy"
                return f"feature_{i}"
            top_feats = "; ".join([f"{fname(int(i))}:{zs[int(i)]:+.2f}σ" for i in top_idx[np.argsort(-contrib[top_idx])]])
            l2 = float(np.linalg.norm(zs))
        return {
            "rel_path": row["rel_path"],
            "expected": int(row["expected"]),
            "predicted": int(row["predicted"]),
            "zero_features": bool(row["zero_features"]),
            "z_l2_distance": l2,
            "top_feature_zscores": top_feats,
            "ref_group": ref_name,
        }

    per_sample_rows = [per_sample_summary(r) for _, r in miscls_df.iterrows()]
    per_sample_df = pd.DataFrame(per_sample_rows)
    per_sample_csv = out_dir / "misclassified_per_sample_deviation.csv"
    per_sample_df.to_csv(per_sample_csv, index=False)

    # Markdown report
    report = [
        "# Misclassification Analysis Report",
        "",
        f"- Samples: {stats['Total']} (TP={stats['TP']}, TN={stats['TN']}, FP={stats['FP']}, FN={stats['FN']})",
        f"- Misclassified: {stats['FP'] + stats['FN']} (FP={stats['FP']} goodware→malware, FN={stats['FN']} malware→goodware)",
        "",
        "## Key differences",
        f"- FP vs TN top deltas: see `{out_fp_delta.name}`",
        f"- FN vs TP top deltas: see `{out_fn_delta.name}`",
        "",
        "## Per-sample deviation (z-scores vs correct centroid)",
        f"- See `{per_sample_csv.name}` for top 5 feature z-scores per misclassified sample",
        f"- Preview misclassified samples with core features in `misclassified_samples_preview.csv`",
        "",
        "### Notes",
        "- feature_0 ≈ file size in bytes; feature_1 ≈ byte-level entropy",
        "- Rows with zero_features=True indicate failed feature extraction (all-zero vector)",
    ]
    report_md = out_dir / "report.md"
    report_md.write_text("\n".join(report))

    return {
        "miscls_preview": miscls_csv,
        "per_sample": per_sample_csv,
        "fp_deltas": out_fp_delta,
        "fn_deltas": out_fn_delta,
        "report": report_md,
    }


def main():
    # Find repository root by walking up until we find the evaluation CSV
    cur = Path(__file__).resolve().parent
    repo_root: Path | None = None
    for _ in range(6):  # search up to a few levels
        candidate = cur / "challenge_evaluation_results.csv"
        if candidate.exists():
            repo_root = cur
            break
        cur = cur.parent
    if repo_root is None:
        # fallback to known path from workspace structure
        fallback = Path("/home/benchodbaap/DataAna")
        if (fallback / "challenge_evaluation_results.csv").exists():
            repo_root = fallback
        else:
            raise FileNotFoundError("Could not locate repository root containing challenge_evaluation_results.csv")

    outputs = analyze_misclassifications(repo_root)
    print("\n=== Outputs ===")
    for k, v in outputs.items():
        print(f"{k}: {v}")


if __name__ == "__main__":
    main()
