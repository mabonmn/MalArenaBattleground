#!/usr/bin/env python3
"""
Train a 1D-CNN on string-like byte tokens and extracted PE string features.

Design:
- Input: tokenized bytes (0..255) with 256 reserved as PAD + extracted string features
- Uses PEAttributeExtractor to get string counts (paths, URLs, registry, MZ) and PE metadata
- Model: Embedding(257, emb_dim, padding_idx=256) -> multiple Conv1d (k=3,5,7) ->
  global max-pool -> concat -> combine with string features -> MLP -> logits
- Data: CSVs with FilePath (or File_Path/Full_Path) and labels inferred by CSV arg
- Split: 70/15/15 train/val/test
- AMP on CUDA, tqdm progress, best checkpoint by val F1, metrics + threshold sweep

Example:
  python3 train/train_cnn_strings.py \
    --malware-csv /path/malware.csv \
    --goodware-csv /path/goodware.csv \
    --max-len 16384 --batch-size 128 --epochs 5 \
    --out-dir defender/defender/models_cnn
"""
import argparse
import os
import random
from dataclasses import dataclass
from typing import List, Tuple, Dict, Any

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from tqdm import tqdm

# Import PE extractor from separate module
from pe_extractor import PEAttributeExtractor

PAD_IDX = 256


def set_seed(seed: int = 42) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)


def to_tokens(bytez: bytes, max_len: int, strings_only: bool) -> np.ndarray:
    if strings_only:
        # Keep printable ASCII plus common whitespace (\t,\n,\r)
        filtered = bytearray()
        for b in bytez:
            if 32 <= b <= 126 or b in (9, 10, 13):
                filtered.append(b)
        arr = np.frombuffer(bytes(filtered), dtype=np.uint8)
    else:
        arr = np.frombuffer(bytez, dtype=np.uint8)
    if arr.size > max_len:
        arr = arr[:max_len]
    if arr.size < max_len:
        arr = np.pad(arr, (0, max_len - arr.size), mode='constant', constant_values=PAD_IDX)
    return arr.astype(np.int64)


def extract_string_features(attributes: Dict[str, Any]) -> np.ndarray:
    """Extract key string-based features from PE attributes for the CNN."""
    features = [
        float(attributes.get('size', 0)) / 1e6,  # Size in MB
        float(attributes.get('entropy', 0)),
        float(attributes.get('string_paths', 0)),
        float(attributes.get('string_urls', 0)), 
        float(attributes.get('string_registry', 0)),
        float(attributes.get('string_MZ', 0)),
        float(attributes.get('imports', 0)),
        float(attributes.get('exports', 0)),
        float(attributes.get('numberof_sections', 0)),
        float(attributes.get('has_debug', 0)),
        float(attributes.get('has_relocations', 0)),
        float(attributes.get('has_resources', 0)),
        float(attributes.get('has_signature', 0)),
        float(attributes.get('has_tls', 0)),
        float(len(attributes.get('functions', '').split())),  # Function count
        float(len(attributes.get('libraries', '').split())),  # Library count
    ]
    return np.array(features, dtype=np.float32)


class PEStringDataset(Dataset):
    def __init__(self, df: pd.DataFrame, max_len: int, strings_only: bool) -> None:
        self.paths = df['FilePath'].tolist()
        self.labels = df['label'].astype(int).tolist()
        self.max_len = int(max_len)
        self.strings_only = bool(strings_only)
        self.max_file_size = 50 * 1024 * 1024  # 50 MB in bytes

    def __len__(self) -> int:
        return len(self.paths)

    def __getitem__(self, idx: int):
        file_path = self.paths[idx]
        y = self.labels[idx]
        
        try:
            # Check file size before processing
            file_size = os.path.getsize(file_path)
            if file_size > self.max_file_size:
                # Use zeros for oversized files
                tokens = np.full(self.max_len, PAD_IDX, dtype=np.int64)
                string_feats = np.zeros(16, dtype=np.float32)
            else:
                with open(file_path, 'rb') as f:
                    bytez = f.read()
                
                # Extract PE attributes using your extractor
                extractor = PEAttributeExtractor(bytez)
                attributes = extractor.extract()
                
                # Get byte tokens
                tokens = to_tokens(bytez, self.max_len, self.strings_only)
                
                # Get string features
                string_feats = extract_string_features(attributes)
                
        except Exception as e:
            # Use defaults for any error
            tokens = np.full(self.max_len, PAD_IDX, dtype=np.int64)
            string_feats = np.zeros(16, dtype=np.float32)
            
        x_tokens = torch.from_numpy(tokens)
        x_strings = torch.from_numpy(string_feats)
        return (x_tokens, x_strings), torch.tensor(y, dtype=torch.float32)


class TextCNNWithStrings(nn.Module):
    def __init__(self, emb_dim: int, num_kernels: int, kernels: Tuple[int, ...], num_string_features: int = 16, num_classes: int = 1):
        super().__init__()
        # Larger token embedding and multi-layer CNN
        self.embed = nn.Embedding(num_embeddings=PAD_IDX + 1, embedding_dim=emb_dim, padding_idx=PAD_IDX)
        
        # Multiple CNN layers with different kernel sizes
        self.convs_layer1 = nn.ModuleList([nn.Conv1d(in_channels=emb_dim, out_channels=num_kernels, kernel_size=k) for k in kernels])
        self.convs_layer2 = nn.ModuleList([nn.Conv1d(in_channels=num_kernels, out_channels=num_kernels * 2, kernel_size=k) for k in kernels])
        
        # Batch normalization for stability
        self.bn1 = nn.ModuleList([nn.BatchNorm1d(num_kernels) for _ in kernels])
        self.bn2 = nn.ModuleList([nn.BatchNorm1d(num_kernels * 2) for _ in kernels])
        
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(0.3)
        self.dropout_heavy = nn.Dropout(0.5)
        
        # Larger string feature processing with multiple layers
        self.string_fc1 = nn.Linear(num_string_features, 64)
        self.string_fc2 = nn.Linear(64, 128)
        self.string_bn = nn.BatchNorm1d(128)
        
        # Larger combined features with deeper MLP
        combined_size = (num_kernels * 2) * len(kernels) + 128
        self.fc1 = nn.Linear(combined_size, 512)
        self.fc2 = nn.Linear(512, 256)
        self.fc3 = nn.Linear(256, 128)
        self.out = nn.Linear(128, num_classes)
        
        # Batch normalization for FC layers
        self.fc_bn1 = nn.BatchNorm1d(512)
        self.fc_bn2 = nn.BatchNorm1d(256)

    def forward(self, x_tokens: torch.Tensor, x_strings: torch.Tensor) -> torch.Tensor:
        # Token CNN path with multiple layers
        x = self.embed(x_tokens)           # (batch, seq_len, emb)
        x = x.transpose(1, 2)              # (batch, emb, seq_len)
        
        # First CNN layer
        cnn_feats_l1 = []
        for i, conv in enumerate(self.convs_layer1):
            h = self.relu(self.bn1[i](conv(x)))     # (batch, num_kernels, L')
            h = torch.max(h, dim=2).values          # global max-pool -> (batch, num_kernels)
            cnn_feats_l1.append(h)
        
        # Second CNN layer (applied to each branch separately)
        cnn_feats_l2 = []
        for i, (conv1_out, conv2) in enumerate(zip(cnn_feats_l1, self.convs_layer2)):
            # Reshape for conv2: add sequence dimension back
            h_reshaped = conv1_out.unsqueeze(2).expand(-1, -1, 100)  # (batch, num_kernels, 100)
            h = self.relu(self.bn2[i](conv2(h_reshaped)))           # (batch, num_kernels*2, L'')
            h = torch.max(h, dim=2).values                          # global max-pool -> (batch, num_kernels*2)
            cnn_feats_l2.append(h)
        
        cnn_out = torch.cat(cnn_feats_l2, dim=1)   # (batch, num_kernels*2 * len(kernels))
        cnn_out = self.dropout(cnn_out)
        
        # Enhanced string features path
        string_out = self.relu(self.string_fc1(x_strings))  # (batch, 64)
        string_out = self.dropout(string_out)
        string_out = self.relu(self.string_bn(self.string_fc2(string_out)))  # (batch, 128)
        string_out = self.dropout(string_out)
        
        # Combine features with deeper MLP
        combined = torch.cat([cnn_out, string_out], dim=1)  # (batch, combined_size)
        
        # Deep fully connected layers
        z = self.relu(self.fc_bn1(self.fc1(combined)))      # (batch, 512)
        z = self.dropout_heavy(z)
        z = self.relu(self.fc_bn2(self.fc2(z)))             # (batch, 256)
        z = self.dropout(z)
        z = self.relu(self.fc3(z))                          # (batch, 128)
        z = self.dropout(z)
        
        logits = self.out(z).squeeze(1)
        return logits


@dataclass
class Split:
    train: pd.DataFrame
    val: pd.DataFrame
    test: pd.DataFrame


def load_data(malware_csv: str, goodware_csv: str) -> pd.DataFrame:
    def read_and_normalize(csv_path: str, label: int) -> pd.DataFrame:
        df = pd.read_csv(csv_path, dtype=str)
        # Handle multiple column name formats
        path_col = None
        for col in ['FilePath', 'File_Path', 'Full_Path']:
            if col in df.columns:
                path_col = col
                break
        
        if path_col is None:
            raise ValueError(f"CSV {csv_path} must have 'FilePath', 'File_Path', or 'Full_Path' column")
            
        df = df[[path_col]].copy().rename(columns={path_col: 'FilePath'})
        df['label'] = label
        df['FilePath'] = df['FilePath'].astype(str)
        df = df.dropna(subset=['FilePath'])
        df = df[df['FilePath'].str.len() > 0]
        exists = df['FilePath'].apply(lambda p: os.path.isfile(p))
        return df[exists].reset_index(drop=True)

    dm = read_and_normalize(malware_csv, 1)
    dg = read_and_normalize(goodware_csv, 0)
    df = pd.concat([dm, dg], ignore_index=True)
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    print(f"Loaded: malware={len(dm)} goodware={len(dg)} total={len(df)}")
    if len(df) == 0:
        raise RuntimeError("No valid files found after filtering existence checks.")
    return df


def split_df(df: pd.DataFrame, train_frac=0.70, val_frac=0.15) -> Split:
    n = len(df)
    n_train = int(n * train_frac)
    n_val = int(n * val_frac)
    train_df = df.iloc[:n_train]
    val_df = df.iloc[n_train:n_train + n_val]
    test_df = df.iloc[n_train + n_val:]
    print(f"Split sizes: train={len(train_df)} val={len(val_df)} test={len(test_df)}")
    return Split(train=train_df.reset_index(drop=True), val=val_df.reset_index(drop=True), test=test_df.reset_index(drop=True))


def make_loaders(split: Split, max_len: int, batch_size: int, num_workers: int, device: torch.device, strings_only: bool):
    pin = device.type == 'cuda'
    train_loader = DataLoader(PEStringDataset(split.train, max_len, strings_only), batch_size=batch_size, shuffle=True, num_workers=num_workers, pin_memory=pin)
    val_loader = DataLoader(PEStringDataset(split.val, max_len, strings_only), batch_size=batch_size, shuffle=False, num_workers=num_workers, pin_memory=pin)
    test_loader = DataLoader(PEStringDataset(split.test, max_len, strings_only), batch_size=batch_size, shuffle=False, num_workers=num_workers, pin_memory=pin)
    return train_loader, val_loader, test_loader


def compute_metrics(y_true: np.ndarray, y_prob: np.ndarray, thresh: float):
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


def evaluate(model: nn.Module, loader: DataLoader, device: torch.device):
    model.eval()
    loss_fn = nn.BCEWithLogitsLoss()
    losses: List[float] = []
    probs: List[float] = []
    labels: List[int] = []
    with torch.no_grad():
        for (x_tokens, x_strings), y in loader:
            x_tokens = x_tokens.to(device, non_blocking=True)
            x_strings = x_strings.to(device, non_blocking=True)
            y = y.to(device, non_blocking=True)
            logits = model(x_tokens, x_strings)
            loss = loss_fn(logits, y)
            losses.append(loss.item())
            probs.extend(torch.sigmoid(logits).detach().cpu().numpy().tolist())
            labels.extend(y.detach().cpu().numpy().tolist())
    return float(np.mean(losses) if losses else 0.0), np.array(labels, dtype=np.int32), np.array(probs, dtype=np.float32)


def train_loop(model: nn.Module, train_loader: DataLoader, val_loader: DataLoader, device: torch.device, epochs: int, lr: float, out_dir: str):
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    scaler = torch.cuda.amp.GradScaler(enabled=(device.type == 'cuda'))
    loss_fn = nn.BCEWithLogitsLoss()

    best_f1 = -1.0
    best_path = os.path.join(out_dir, 'cnn_strings_best.pt')
    final_path = os.path.join(out_dir, 'cnn_strings_final.pt')
    os.makedirs(out_dir, exist_ok=True)

    for epoch in range(1, epochs + 1):
        model.train()
        pbar = tqdm(train_loader, desc=f"Epoch {epoch}/{epochs}")
        running_loss = 0.0
        for (x_tokens, x_strings), y in pbar:
            x_tokens = x_tokens.to(device, non_blocking=True)
            x_strings = x_strings.to(device, non_blocking=True)
            y = y.to(device, non_blocking=True)

            optimizer.zero_grad(set_to_none=True)
            with torch.cuda.amp.autocast(enabled=(device.type == 'cuda')):
                logits = model(x_tokens, x_strings)
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
        meets = (m['fpr'] <= 0.01) and (m['fnr'] <= 0.10)
        score = (m['f1'] + 2.0) if meets else m['f1']
        if score > best_score:
            best_score = score
            best_thr = float(thr)
    csv_path = os.path.join(out_dir, 'cnn_strings_threshold_sweep.csv')
    with open(csv_path, 'w') as f:
        for row in rows:
            if isinstance(row[0], str):
                f.write(','.join(map(str, row)) + '\n')
            else:
                f.write(','.join(map(lambda x: f"{x}", row)) + '\n')
    with open(os.path.join(out_dir, 'cnn_strings_best_threshold.txt'), 'w') as f:
        f.write(str(best_thr))
    print(f"Wrote threshold_sweep and best_threshold (best={best_thr}) to {out_dir}")
    return best_thr


def write_metrics(out_dir: str, y_true: np.ndarray, y_prob: np.ndarray, threshold: float) -> None:
    m, _ = compute_metrics(y_true, y_prob, threshold)
    lines = [
        f"Threshold: {threshold}",
        f"TP: {m['TP']}", f"TN: {m['TN']}", f"FP: {m['FP']}", f"FN: {m['FN']}",
        f"Accuracy: {m['accuracy']:.4f}", f"Precision: {m['precision']:.4f}",
        f"Recall: {m['recall']:.4f}", f"F1: {m['f1']:.4f}",
        f"FPR: {m['fpr']:.4f}", f"FNR: {m['fnr']:.4f}",
    ]
    with open(os.path.join(out_dir, 'cnn_strings_metrics.txt'), 'w') as f:
        f.write('\n'.join(lines) + '\n')
    print("Saved cnn_strings_metrics.txt")


def main() -> None:
    ap = argparse.ArgumentParser(description="Train a 1D-CNN on string-like byte tokens and PE string features")
    ap.add_argument('--malware-csv', required=True, help='CSV of malware file paths (FilePath, File_Path or Full_Path)')
    ap.add_argument('--goodware-csv', required=True, help='CSV of goodware file paths (FilePath, File_Path or Full_Path)')
    ap.add_argument('--epochs', type=int, default=1)
    ap.add_argument('--batch-size', type=int, default=256)
    ap.add_argument('--lr', type=float, default=1e-3)
    ap.add_argument('--max-len', type=int, default=16384, help='Max tokens per file (sequence length)')
    ap.add_argument('--num-workers', type=int, default=4)
    ap.add_argument('--emb-dim', type=int, default=8)
    ap.add_argument('--num-kernels', type=int, default=64)
    ap.add_argument('--kernels', type=int, nargs='+', default=[3,5,7])
    ap.add_argument('--strings-only', action='store_true', help='Keep only printable ASCII tokens')
    ap.add_argument('--out-dir', default='defender/defender/models_cnn', help='Where to save models and metrics')
    ap.add_argument('--seed', type=int, default=42)
    args = ap.parse_args()

    set_seed(args.seed)

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Using device: {device}")

    df = load_data(args.malware_csv, args.goodware_csv)
    df = df.sample(frac=0.03, random_state=args.seed).reset_index(drop=True)
    split = split_df(df, 0.70, 0.15)
    train_loader, val_loader, test_loader = make_loaders(split, args.max_len, args.batch_size, args.num_workers, device, args.strings_only)

    model = TextCNNWithStrings(emb_dim=args.emb_dim, num_kernels=args.num_kernels, kernels=tuple(args.kernels)).to(device)
    print(f"Model parameters: {sum(p.numel() for p in model.parameters())}")

    train_loop(model, train_loader, val_loader, device, args.epochs, args.lr, args.out_dir)

    # Load best for testing if present
    best_path = os.path.join(args.out_dir, 'cnn_strings_best.pt')
    if os.path.isfile(best_path):
        model.load_state_dict(torch.load(best_path, map_location=device))

    # Test evaluation
    test_loss, y_true, y_prob = evaluate(model, test_loader, device)
    print(f"Test loss: {test_loss:.4f}")
    best_thr = threshold_sweep(y_true, y_prob, args.out_dir)
    write_metrics(args.out_dir, y_true, y_prob, best_thr)


if __name__ == '__main__':
    main()
