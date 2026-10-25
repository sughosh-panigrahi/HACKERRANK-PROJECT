"""Deletion audit agent scaffold.

Deterministic core (identity graph + rules engine). LLM/OCR only for media.
Edit CONFIG to match the real CSV headers and the schema in problem_statement.md.
"""
import csv
import glob
import json
import os
import re
import sys
from collections import defaultdict

# ---------------- CONFIG: adjust to real headers ----------------
CONFIG = {
    "requests_file": "dataset/deletion_requests.csv",
    "rules_file": "dataset/deletion_rules.csv",
    "data_glob": "dataset/*.csv",          # all other record stores
    "request_id_col": "request_id",
    "request_person_col": "user_id",
    "request_flag_col": "deletion_requested",   # yes/no style column, if any
    "rule_store_col": "store_type",             # which kind of copy
    "rule_action_col": "required_action",       # delete / redact / anonymize / retain
    "rule_allowed_ids_col": "allowed_identifiers",  # for retained records
    "output_file": "output.csv",
    "output_cols": [
        "request_id",
        "status",
        "exposed_records",
        "recreating_processes",
        "remediation_steps"
    ],
}

ID_FIELDS_HINT = ("email", "phone", "user_id", "account_id", "device_id", "customer_id", "id")

# ---------------- normalization ----------------
def norm(v: str) -> str:
    if not v:
        return ""
    v = str(v).strip().lower()
    
    # Handle email subaddressing
    if "@" in v:
        local, _, dom = v.partition("@")
        return f"{local.split('+')[0]}@{dom}"
    
    # Handle phone numbers
    digits = re.sub(r"\D", "", v)
    if len(digits) >= 7 and re.fullmatch(r"[\d\s()+\.-]+", v):
        return digits[-10:]
        
    return v

def read_csv(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))

# ---------------- identity graph (union-find) ----------------
class UF:
    def __init__(self):
        self.p = {}

    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        root_a = self.find(a)
        root_b = self.find(b)
        if root_a != root_b:
            self.p[root_a] = root_b

def row_identifiers(row):
    out = []
    for k, v in row.items():
        if v and any(h in k.lower() for h in ID_FIELDS_HINT):
            n = norm(v)
            if n:
                out.append(n)
    return out

def build_graph(tables):
    uf = UF()
    for rows in tables.values():
        for r in rows:
            ids = row_identifiers(r)
            if ids:
                first = ids[0]
                uf.find(first)
                for i in ids[1:]:
                    uf.union(first, i)
    return uf

# ---------------- media (OCR / VLM Stub) ----------------
def extract_media_text(path):
    cache = path + ".txt"
    if os.path.exists(cache):
        with open(cache, encoding="utf-8") as f:
            return f.read()
    return ""

# ---------------- audit ----------------
def audit(req, tables, rules_by_store, uf):
    c = CONFIG
    
    # Check if request is active/applicable
    flag = (req.get(c["request_flag_col"], "yes") or "yes").strip().lower()
    if flag in ("no", "false", "0", "n"):
        return dict(status="NOT_APPLICABLE", exposed=[], procs=[], steps=[])

    # Find target cluster for the request
    seeds = [norm(v) for k, v in req.items() if v and any(h in k.lower() for h in ID_FIELDS_HINT)]
    cluster = {uf.find(s) for s in seeds if s}

    if not cluster:
        return dict(status="COMPLETE", exposed=[], procs=[], steps=[])

    exposed, procs = [], []

    for name, rows in tables.items():
        store_key = name.rsplit(".", 1)[0].lower()
        rule = rules_by_store.get(store_key, {})
        action = (rule.get(c["rule_action_col"]) or "delete").strip().lower()
        allowed_ids = set(
            norm(x) for x in (rule.get(c["rule_allowed_ids_col"]) or "").split(",") if x.strip()
        )

        for i, r in enumerate(rows):
            row_ids = row_identifiers(r)
            if not any(uf.find(x) in cluster for x in row_ids):
                continue

            record_ref = f"{name}:{i}"
            blob = " ".join(str(v).lower() for v in r.values())

            # Check if this table represents a process / cron sync
            if any(w in name.lower() for w in ("sync", "job", "import", "restore", "process")):
                if any(w in blob for w in ("active", "enabled", "running", "true", "1")):
                    procs.append(record_ref)
            else:
                # Rule Evaluation
                if action == "retain":
                    violating_ids = [x for x in row_ids if x not in allowed_ids]
                    if violating_ids:
                        exposed.append(record_ref)
                elif action in ("delete", "redact", "anonymize"):
                    already_treated = (
                        r.get("status", "").lower() in ("deleted", "anonymized", "redacted") or
                        r.get("is_deleted", "").lower() in ("true", "1", "yes")
                    )
                    if not already_treated:
                        exposed.append(record_ref)

    complete = len(exposed) == 0 and len(procs) == 0
    
    steps = []
    if procs:
        steps.extend([f"Disable background process {p}" for p in procs])
    if exposed:
        steps.extend([f"Treat record {e} according to retention rules" for e in exposed])
    
    if not complete:
        steps.append("Re-scan identity graph to confirm full deletion compliance.")

    return dict(
        status="COMPLETE" if complete else "INCOMPLETE",
        exposed=exposed,
        procs=procs,
        steps=steps
    )

def main():
    c = CONFIG
    reqs = read_csv(c["requests_file"])
    rules = read_csv(c["rules_file"])
    
    rules_by_store = {}
    for r in rules:
        store = (r.get(c["rule_store_col"]) or "").strip().lower()
        if store:
            rules_by_store[store] = r

    req_abs = os.path.abspath(c["requests_file"]) if os.path.exists(c["requests_file"]) else ""
    rule_abs = os.path.abspath(c["rules_file"]) if os.path.exists(c["rules_file"]) else ""
    
    tables = {}
    for p in glob.glob(c["data_glob"]):
        p_abs = os.path.abspath(p)
        if p_abs not in (req_abs, rule_abs):
            tables[os.path.basename(p)] = read_csv(p)

    uf = build_graph(tables)

    with open(c["output_file"], "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(c["output_cols"])
        
        for r in reqs:
            req_id = r.get(c["request_id_col"])
            res = audit(r, tables, rules_by_store, uf)
            writer.writerow([
                req_id,
                res["status"],
                json.dumps(res["exposed"]),
                json.dumps(res["procs"]),
                json.dumps(res["steps"])
            ])
            
    print(f"Audit complete! Results written to {CONFIG['output_file']}")

def evaluate(pred_path, gold_path, key="request_id", fields=("status",)):
    pred = {r[key]: r for r in read_csv(pred_path)}
    gold = {r[key]: r for r in read_csv(gold_path)}
    for fld in fields:
        hit = sum(1 for k, g in gold.items() if k in pred and pred[k].get(fld) == g.get(fld))
        print(f"{fld}: {hit}/{len(gold)} = {hit/max(len(gold),1):.2%}")

if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "eval":
        evaluate("output.csv", sys.argv[2])
    else:
        main()
