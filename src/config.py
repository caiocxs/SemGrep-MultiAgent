"""
Loads a model combo (configs/combos/combo_<name>.toml) and resolves each role
against the model catalog (configs/models.toml), so the pipeline can ask
"which model/settings does the generator use?" with a single call.

    python -m src.config --combo B              # prints the resolved roles and which GGUF files are missing
    python -m src.config --combo B --download   # downloads the missing GGUF files into .models/

Downloads use only the standard library, so they behave the same on Windows
and Linux (no curl/wget needed).
"""

import argparse
import shutil
import tomllib
import urllib.request
from pathlib import Path

CONFIGS_DIR = Path("configs")
MODELS_DIR = Path(".models")
ROLES = ["detector", "generator", "corrector", "critic", "merger"]


def model_url(model):
    return f"https://huggingface.co/{model['repo']}/resolve/main/{model['file']}"


def load_combo(name):
    """
    Returns {"name", "description", "loop", "roles": {role: settings}} where
    each role's settings are the combo [defaults] overlaid by the role's own
    table, plus the full catalog entry under "model" and its local "path".
    """
    catalog = tomllib.loads((CONFIGS_DIR / "models.toml").read_text(encoding="utf-8"))
    combo_path = CONFIGS_DIR / "combos" / f"combo_{name.lower()}.toml"
    if not combo_path.exists():
        raise FileNotFoundError(f"Combo not found: {combo_path}")
    combo = tomllib.loads(combo_path.read_text(encoding="utf-8"))

    roles = {}
    for role in ROLES:
        if role not in combo.get("roles", {}):
            raise KeyError(f"Combo {name} does not define role '{role}'")
        settings = {**combo.get("defaults", {}), **combo["roles"][role]}
        key = settings["model"]
        if key not in catalog:
            raise KeyError(f"Combo {name}, role {role}: model '{key}' not in models.toml")
        settings["model"] = {"key": key, **catalog[key]}
        settings["path"] = MODELS_DIR / catalog[key]["file"]
        roles[role] = settings

    return {
        "name": combo.get("name", name),
        "description": combo.get("description", ""),
        "loop": combo.get("loop", {}),
        "roles": roles,
    }


def download_model(model, dest_dir=MODELS_DIR):
    """
    Streams the GGUF into <dest>.part and renames it only when complete, so an
    interrupted download never leaves a truncated file that looks valid.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / model["file"]
    part = dest.with_name(dest.name + ".part")
    url = model_url(model)
    print(f"Downloading {model['file']} ({model['size_gb']} GB)...")
    with urllib.request.urlopen(url) as response, part.open("wb") as out:
        total = int(response.headers.get("Content-Length", 0))
        done = 0
        while chunk := response.read(1 << 20):
            out.write(chunk)
            done += len(chunk)
            if total:
                print(f"\r  {done / total:6.1%} ({done / 1e9:.2f}/{total / 1e9:.2f} GB)", end="", flush=True)
    print()
    shutil.move(part, dest)
    print(f"[✓] Saved to {dest}")


def main():
    parser = argparse.ArgumentParser(description="Show a model combo and which of its GGUF files are missing.")
    parser.add_argument("--combo", required=True, help="Combo name (A, B, C...)")
    parser.add_argument("--download", action="store_true", help="Download the missing GGUF files into .models/")
    args = parser.parse_args()

    combo = load_combo(args.combo)
    print(f"Combo {combo['name']}: {combo['description']}\n")

    missing = {}
    for role, s in combo["roles"].items():
        m = s["model"]
        status = "ok" if s["path"].exists() else "MISSING"
        print(f"  {role:<10} {m['name']} ({m['quant']}, {m['size_gb']} GB) n_ctx={s['n_ctx']} [{status}]")
        if status == "MISSING":
            missing[m["file"]] = m

    if not missing:
        return
    if args.download:
        print()
        for m in missing.values():
            download_model(m)
    else:
        print(f"\nMissing files (run again with --download, or fetch manually into {MODELS_DIR}/):")
        for m in missing.values():
            print(f"  {model_url(m)}")


if __name__ == "__main__":
    main()
