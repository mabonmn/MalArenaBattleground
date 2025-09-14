#!/usr/bin/env python3
"""
Train a simple MalConv-like model from malware/goodware CSVs.

Features:
- Robust CSV loading (dtype=str), column normalization (Full_Path -> File_Path)
- Filters to existing files, drops invalids
- BinaryDataset reading up to max_bytes and normalizing to [0,1]
- Train/val/test split (70/15/15)
- AMP on CUDA when available (safe on CPU)
- tqdm progress bars
- Best checkpoint saving (by val F1) to malconv_model_best.pt and final malconv_model.pt
- Test evaluation with metrics.txt
- Threshold sweep (0.50..0.999) producing threshold_sweep.csv and best_threshold.txt

Usage example:
  python3 train/train_malconv.py \
    --malware-csv /path/malware.csv \
    --goodware-csv /path/goodware.csv \
    --epochs 5 --batch-size 64 --max-bytes 1048576 \
    --out-dir defender/defender/models

CSV schema: expects a path column named File_Path (or Full_Path will be auto-renamed).
"""
from __future__ import annotations

import argparse
import os
import random
from dataclasses import dataclass
from typing import List, Tuple

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from tqdm import tqdm


def set_seed(seed: int = 42) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)


class BinaryDataset(Dataset):
    def __init__(self, df: pd.DataFrame, max_bytes: int) -> None:
        self.paths = df['File_Path'].tolist()
        self.labels = df['label'].astype(int).tolist()
        self.max_bytes = int(max_bytes)

    def __len__(self) -> int:
        return len(self.paths)

    def __getitem__(self, idx: int):
        path = self.paths[idx]
        y = self.labels[idx]
        if not isinstance(path, str) or not os.path.isfile(path):
            raise FileNotFoundError(f"Invalid path at index {idx}: {path}")
        with open(path, 'rb') as f:
            b = f.read(self.max_bytes)
        if len(b) < self.max_bytes:
            b = b + (b'\x00' * (self.max_bytes - len(b)))
        arr = np.frombuffer(b, dtype=np.uint8).astype(np.float32) / 255.0
        x = torch.from_numpy(arr)
        return x, torch.tensor(y, dtype=torch.float32)


class MalConv(nn.Module):
    def __init__(self, max_bytes: int) -> None:
        super().__init__()
        self.max_bytes = int(max_bytes)
        self.conv1 = nn.Conv1d(1, 16, kernel_size=500, stride=500)
        self.relu = nn.ReLU()
        self.fc1 = nn.Linear(16 * (self.max_bytes // 500), 64)
        self.fc2 = nn.Linear(64, 1)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (batch, bytes)
        x = x.unsqueeze(1)  # (batch, 1, bytes)
        x = self.conv1(x)
        x = self.relu(x)
        x = x.view(x.size(0), -1)
        x = self.fc1(x)
        x = self.relu(x)
        x = self.fc2(x)
        return x.squeeze(1)  # logits


def load_data(malware_csv: str, goodware_csv: str) -> pd.DataFrame:
    def read_and_normalize(csv_path: str, label: int) -> pd.DataFrame:
        df = pd.read_csv(csv_path, dtype=str)
        # Normalize path column
        if 'File_Path' not in df.columns and 'Full_Path' in df.columns:
            df = df.rename(columns={'Full_Path': 'File_Path'})
        if 'File_Path' not in df.columns:
            raise ValueError(f"CSV {csv_path} must have 'File_Path' (or 'Full_Path') column")
        df = df[['File_Path']].copy()
        df['label'] = label
        # Clean up
        df['File_Path'] = df['File_Path'].astype(str)
        df = df.dropna(subset=['File_Path'])
        df = df[df['File_Path'].str.len() > 0]
        # Only existing files
        exists_mask = df['File_Path'].apply(lambda p: os.path.isfile(p))
        df = df[exists_mask]
        return df.reset_index(drop=True)

    df_mal = read_and_normalize(malware_csv, 1)
    df_good = read_and_normalize(goodware_csv, 0)
    df = pd.concat([df_mal, df_good], axis=0, ignore_index=True)
    # Shuffle
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    print(f"Loaded: malware={len(df_mal)} goodware={len(df_good)} total={len(df)}")
    if len(df) == 0:
        raise RuntimeError("No valid files found after filtering existence checks.")
    print(df.head(5))
    return df


@dataclass
class Split:
    train: pd.DataFrame
    val: pd.DataFrame
    test: pd.DataFrame


def split_df(df: pd.DataFrame, train_frac=0.70, val_frac=0.15) -> Split:
    n = len(df)
    n_train = int(n * train_frac)
    n_val = int(n * val_frac)
    train_df = df.iloc[:n_train]
    val_df = df.iloc[n_train:n_train + n_val]
    test_df = df.iloc[n_train + n_val:]
    print(f"Split sizes: train={len(train_df)} val={len(val_df)} test={len(test_df)}")
    return Split(train=train_df.reset_index(drop=True),
                 val=val_df.reset_index(drop=True),
                 test=test_df.reset_index(drop=True))


def make_loaders(split: Split, max_bytes: int, batch_size: int, num_workers: int, device: torch.device):
    pin = device.type == 'cuda'
    train_loader = DataLoader(BinaryDataset(split.train, max_bytes), batch_size=batch_size, shuffle=True,
                              num_workers=num_workers, pin_memory=pin)
    val_loader = DataLoader(BinaryDataset(split.val, max_bytes), batch_size=batch_size, shuffle=False,
                            num_workers=num_workers, pin_memory=pin)
    test_loader = DataLoader(BinaryDataset(split.test, max_bytes), batch_size=batch_size, shuffle=False,
                             num_workers=num_workers, pin_memory=pin)
    return train_loader, val_loader, test_loader


def compute_metrics(y_true: np.ndarray, y_prob: np.ndarray, thresh: float) -> Tuple[dict, np.ndarray]:
    y_pred = (y_prob >= thresh).astype(np.int32)
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    acc = (tp + tn) / max(1, (tp + tn + fp + fn))
    prec = tp / max(1, (tp + fp))
    rec = tp / max(1, (tp + fn))
    f1 = 2 * prec * rec / max(1e-12, (prec + rec)) if (prec + rec) > 0 else 0.0
    fpr = fp / max(1, (fp + tn))
    fnr = fn / max(1, (fn + tp))
    return {
        'TP': tp, 'TN': tn, 'FP': fp, 'FN': fn,
        'accuracy': acc, 'precision': prec, 'recall': rec, 'f1': f1,
        'fpr': fpr, 'fnr': fnr
    }, y_pred


def evaluate(model: nn.Module, loader: DataLoader, device: torch.device) -> Tuple[float, np.ndarray, np.ndarray]:
    model.eval()
    loss_fn = nn.BCEWithLogitsLoss()
    losses: List[float] = []
    probs: List[float] = []
    labels: List[int] = []
    with torch.no_grad():
        for x, y in loader:
            x = x.to(device, non_blocking=True)
            y = y.to(device, non_blocking=True)
            logits = model(x)
            loss = loss_fn(logits, y)
            losses.append(loss.item())
            probs.extend(torch.sigmoid(logits).cpu().numpy().tolist())
            labels.extend(y.cpu().numpy().tolist())
    return float(np.mean(losses) if losses else 0.0), np.array(labels, dtype=np.int32), np.array(probs, dtype=np.float32)


def train_loop(model: nn.Module, train_loader: DataLoader, val_loader: DataLoader, device: torch.device,
               epochs: int, lr: float, out_dir: str) -> None:
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    scaler = torch.cuda.amp.GradScaler(enabled=(device.type == 'cuda'))
    loss_fn = nn.BCEWithLogitsLoss()

    best_f1 = -1.0
    best_path = os.path.join(out_dir, 'malconv_model_best.pt')
    final_path = os.path.join(out_dir, 'malconv_model.pt')
    os.makedirs(out_dir, exist_ok=True)

    for epoch in range(1, epochs + 1):
        model.train()
        pbar = tqdm(train_loader, desc=f"Epoch {epoch}/{epochs}")
        running_loss = 0.0
        for x, y in pbar:
            x = x.to(device, non_blocking=True)
            y = y.to(device, non_blocking=True)

            optimizer.zero_grad(set_to_none=True)
            with torch.cuda.amp.autocast(enabled=(device.type == 'cuda')):
                logits = model(x)
                loss = loss_fn(logits, y)
            scaler.scale(loss).backward()
            scaler.step(optimizer)
            scaler.update()

            running_loss += loss.item()
            pbar.set_postfix(loss=f"{running_loss / max(1, pbar.n):.4f}")

        # Validation
        val_loss, y_true, y_prob = evaluate(model, val_loader, device)
        metrics, _ = compute_metrics(y_true, y_prob, thresh=0.5)
        f1 = metrics['f1']
        print(f"Val: loss={val_loss:.4f} f1={f1:.4f} acc={metrics['accuracy']:.4f} fpr={metrics['fpr']:.4f} fnr={metrics['fnr']:.4f}")
        if f1 > best_f1:
            best_f1 = f1
            torch.save(model.state_dict(), best_path)
            print(f"Saved best model to {best_path}")

    # Save final
    torch.save(model.state_dict(), final_path)
    print(f"Saved final model to {final_path}")


def threshold_sweep(y_true: np.ndarray, y_prob: np.ndarray, out_dir: str) -> float:
    rows = [("threshold", "f1", "accuracy", "precision", "recall", "fpr", "fnr", "TP", "TN", "FP", "FN")]
    best_thr = 0.5
    best_score = -1.0
    for thr in list(np.arange(0.50, 1.000, 0.005)) + [0.999]:
        m, _ = compute_metrics(y_true, y_prob, thr)
        rows.append((thr, m['f1'], m['accuracy'], m['precision'], m['recall'], m['fpr'], m['fnr'], m['TP'], m['TN'], m['FP'], m['FN']))
        # Preference: meet FPR<=1% and FNR<=10% if possible, else maximize F1
        meets = (m['fpr'] <= 0.01) and (m['fnr'] <= 0.10)
        score = (m['f1'] + 2.0) if meets else m['f1']
        if score > best_score:
            best_score = score
            best_thr = float(thr)
    # Write CSV
    csv_path = os.path.join(out_dir, 'threshold_sweep.csv')
    with open(csv_path, 'w') as f:
        for row in rows:
            if isinstance(row[0], str):
                f.write(','.join(map(str, row)) + '\n')
            else:
                f.write(','.join(map(lambda x: f"{x}", row)) + '\n')
    with open(os.path.join(out_dir, 'best_threshold.txt'), 'w') as f:
        f.write(str(best_thr))
    print(f"Wrote threshold_sweep.csv and best_threshold.txt (best={best_thr}) to {out_dir}")
    return best_thr


def write_metrics(out_dir: str, y_true: np.ndarray, y_prob: np.ndarray, threshold: float) -> None:
    m, y_pred = compute_metrics(y_true, y_prob, threshold)
    lines = [
        f"Threshold: {threshold}",
        f"TP: {m['TP']}", f"TN: {m['TN']}", f"FP: {m['FP']}", f"FN: {m['FN']}",
        f"Accuracy: {m['accuracy']:.4f}", f"Precision: {m['precision']:.4f}",
        f"Recall: {m['recall']:.4f}", f"F1: {m['f1']:.4f}",
        f"FPR: {m['fpr']:.4f}", f"FNR: {m['fnr']:.4f}",
    ]
    with open(os.path.join(out_dir, 'metrics.txt'), 'w') as f:
        f.write('\n'.join(lines) + '\n')
    print("Saved metrics.txt")


def main() -> None:
    ap = argparse.ArgumentParser(description="Train MalConv-like binary classifier")
    ap.add_argument('--malware-csv', required=True, help='CSV of malware file paths')
    ap.add_argument('--goodware-csv', required=True, help='CSV of goodware file paths')
    ap.add_argument('--epochs', type=int, default=3)
    ap.add_argument('--batch-size', type=int, default=128)
    ap.add_argument('--lr', type=float, default=1e-3)
    ap.add_argument('--max-bytes', type=int, default=1_048_576)
    ap.add_argument('--num-workers', type=int, default=8)
    ap.add_argument('--out-dir', default='defender/defender/models', help='Where to save models and metrics')
    ap.add_argument('--seed', type=int, default=42)
    args = ap.parse_args()

    set_seed(args.seed)

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Using device: {device}")

    df = load_data(args.malware_csv, args.goodware_csv)
    split = split_df(df, 0.70, 0.15)
    train_loader, val_loader, test_loader = make_loaders(split, args.max_bytes, args.batch_size, args.num_workers, device)

    model = MalConv(args.max_bytes).to(device)

    train_loop(model, train_loader, val_loader, device, args.epochs, args.lr, args.out_dir)

    # Load best for testing if present
    best_path = os.path.join(args.out_dir, 'malconv_model_best.pt')
    if os.path.isfile(best_path):
        model.load_state_dict(torch.load(best_path, map_location=device))

    # Test evaluation
    test_loss, y_true, y_prob = evaluate(model, test_loader, device)
    print(f"Test loss: {test_loss:.4f}")
    # Sweep and metrics
    best_thr = threshold_sweep(y_true, y_prob, args.out_dir)
    write_metrics(args.out_dir, y_true, y_prob, best_thr)


if __name__ == '__main__':
    main()
