"""Companion script for the paper: (1) serialization audit, (2) feature-group ablation,
(3) time-ordered split. Run next to ML-EdgeIIoT-dataset.csv:  python ablation_and_audit.py
Group A/B/C definitions follow the paper's Section IV; the port sets and lexical tokens
below are the ones to copy from intrusion_detection.py if you edited them there."""
import re, sys, numpy as np, pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score
from xgboost import XGBClassifier

CSV = sys.argv[1] if len(sys.argv) > 1 else "ML-EdgeIIoT-dataset.csv"
LABEL = "Attack_type"
DROP_ID = ["frame.time","ip.src_host","ip.dst_host","arp.src.proto_ipv4","arp.dst.proto_ipv4",
           "tcp.srcport","tcp.dstport","udp.port","icmp.transmit_timestamp","tcp.options",
           "tcp.payload","http.file_data","http.request.full_uri","http.request.uri.query","mqtt.msg"]
DROP_CONST = ["icmp.unused","http.tls_port","dns.qry.type","dns.retransmit_request_in",
              "mqtt.msg_decoded_as","mbtcp.len","mbtcp.trans_id","mbtcp.unit_id"]
SQLI = r"select|union|extractvalue|sleep|%27|sqli"
XSS  = r"script|alert|iframe|xss"
UPL  = r"upload|multipart|hack\.php"
AUTH = r"login|password|user_token|username"

CATS = ["http.request.method","http.referer","http.request.version","mqtt.conack.flags","mqtt.protoname","mqtt.topic"]

def num(s): return pd.to_numeric(s, errors="coerce").fillna(0.0)

def audit(df):
    """Counts of the two zero tokens per class for every object column (paper Table I)."""
    rows = []
    for c in df.columns:
        if df[c].dtype == object:
            s = df[c].astype(str).str.strip()
            for tok in ("0", "0.0"):
                m = (s == tok)
                if m.any():
                    for cl, n in df.loc[m, LABEL].value_counts().items():
                        rows.append((c, tok, cl, int(n)))
    out = pd.DataFrame(rows, columns=["column","token","class","rows"])
    out.to_csv("audit_zero_tokens.csv", index=False)
    print("Serialization audit saved to audit_zero_tokens.csv (first 40 rows):")
    print(out.head(40).to_string())

def entropy(h):
    h = str(h)[:64]
    if len(h) < 2: return 0.0
    p = pd.Series(list(h)).value_counts(normalize=True).values
    return float(-(p * np.log2(p)).sum())

def psfe(df):
    f = pd.DataFrame(index=df.index)
    ps, pd_ = num(df["tcp.srcport"]), num(df["tcp.dstport"])
    mn, mx = np.minimum(ps, pd_), np.maximum(ps, pd_)
    f["psfe_service_port"] = np.where(mn < 1e4, mn, 0.0); f["psfe_ephemeral_port"] = mx
    f["psfe_port_span"] = (ps - pd_).abs(); f["psfe_pkt_direction"] = np.sign(ps - pd_)
    anyp = lambda S: ((ps.isin(S)) | (pd_.isin(S))).astype(float)
    f["psfe_is_http_service"] = anyp([80,443,8080]); f["psfe_is_mqtt_service"] = anyp([1883])
    f["psfe_is_iot_c2_service"] = anyp([4321,3333,5900]); f["psfe_is_boundary_probe"] = anyp([65535])
    f["psfe_udp_active"] = (num(df["udp.port"]) > 0).astype(float)
    clean = lambda c: df[c].astype(str).replace({"0": "", "0.0": "", "nan": ""})
    opt, pay = clean("tcp.options"), clean("tcp.payload")
    f["psfe_tcp_opt_bytelen"] = opt.str.len() // 2
    f["psfe_tcp_opt_has_mss"] = opt.str.startswith("0204").astype(float)
    f["psfe_tcp_opt_has_ts"] = opt.str.contains("080a").astype(float)
    f["psfe_tcp_pay_bytelen"] = pay.str.len() // 2
    f["psfe_tcp_pay_first_byte"] = pay.apply(lambda h: int(h[:2], 16) if len(h) >= 2 and re.fullmatch(r"[0-9a-fA-F]{2}.*", h) else 0)
    f["psfe_tcp_pay_entropy"] = pay.apply(entropy)
    uri, q, body = clean("http.request.full_uri").str.lower(), clean("http.request.uri.query").str.lower(), clean("http.file_data").str.lower()
    f["psfe_http_uri_path_len"] = uri.str.replace(r"^https?://[^/]+", "", regex=True).str.len()
    f["psfe_http_query_len"] = q.str.len(); f["psfe_http_file_data_len"] = body.str.len()
    f["psfe_mqtt_msg_bytelen"] = clean("mqtt.msg").str.len() // 2
    txt = uri + " " + q + " " + body
    f["psfe_app_sqli_flag"] = txt.str.contains(SQLI).astype(float); f["psfe_app_xss_flag"] = txt.str.contains(XSS).astype(float)
    f["psfe_app_upload_flag"] = txt.str.contains(UPL).astype(float); f["psfe_app_auth_flag"] = txt.str.contains(AUTH).astype(float)
    f["psfe_app_timeout_flag"] = txt.str.contains(r"408|400 bad").astype(float)
    return f

def prep(df):
    df = df.copy()
    df["dns.qry.name.len"] = pd.to_numeric(df["dns.qry.name.len"], errors="coerce").fillna(df["dns.qry.name.len"].astype(str).str.len())
    F = psfe(df); core = df.drop(columns=DROP_ID + DROP_CONST + [c for c in ["Attack_label"] if c in df])
    for c in core.columns:
        if core[c].dtype == object and c != LABEL:
            s = core[c].astype(str).str.strip().replace({"0.0": "0", "0.00": "0"}); core[c] = s
    return core, F

def fit_eval(Xtr, Xte, ytr, yte, tag):
    for c in Xtr.columns:
        if c in CATS:
            m = {v: i for i, v in enumerate(Xtr[c].astype(str).unique())}
            Xtr[c] = Xtr[c].astype(str).map(m); Xte[c] = Xte[c].astype(str).map(m).fillna(-1)
        else:
            Xtr[c] = num(Xtr[c]); Xte[c] = num(Xte[c])
    sc = StandardScaler().fit(Xtr); a, b = sc.transform(Xtr), sc.transform(Xte)
    mdl = XGBClassifier(n_estimators=150, max_depth=6, learning_rate=0.1, subsample=0.8,
                        colsample_bytree=0.8, eval_metric="mlogloss", n_jobs=-1, random_state=42).fit(a, ytr)
    p = mdl.predict(b)
    acc = accuracy_score(yte, p)
    mf1 = f1_score(yte, p, average='macro')
    print(f"{tag:60s} acc={acc:.4f} macroF1={mf1:.4f}")
    return acc, mf1

if __name__ == "__main__":
    print(f"Loading dataset: {CSV}")
    df = pd.read_csv(CSV, low_memory=False)
    print("Running serialization audit...")
    audit(df)
    print("Preprocessing and extracting PP-PSFE features...")
    core, F = prep(df)
    y_raw = core.pop(LABEL); classes = {c: i for i, c in enumerate(sorted(y_raw.unique()))}; y = y_raw.map(classes)
    X = pd.concat([core, F], axis=1).replace([np.inf, -np.inf], np.nan)
    keep = X.dropna().drop_duplicates().index; X, y = X.loc[keep], y.loc[keep]
    print("flows after cleaning:", len(X))
    A = [c for c in F.columns if c in ["psfe_service_port","psfe_ephemeral_port","psfe_port_span","psfe_pkt_direction",
         "psfe_is_http_service","psfe_is_mqtt_service","psfe_is_iot_c2_service","psfe_is_boundary_probe","psfe_udp_active"]]
    variants = {"core only (38)": list(core.columns), "core + PP-PSFE (62)": list(X.columns),
                "core + PP-PSFE minus Group A": [c for c in X.columns if c not in A],
                "core + PP-PSFE minus raw-port features": [c for c in X.columns if c not in ["psfe_service_port","psfe_ephemeral_port","psfe_port_span"]],
                "core minus udp.stream/tcp.seq/tcp.ack/icmp.seq_le + PP-PSFE": [c for c in X.columns if c not in ["udp.stream","tcp.seq","tcp.ack","icmp.seq_le"]]}
    
    results = []
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    print("\n--- random stratified split (as in the paper)")
    for k, cols in variants.items():
        acc, mf1 = fit_eval(Xtr[cols].copy(), Xte[cols].copy(), ytr, yte, k)
        results.append({"split": "random stratified", "variant": k, "features": len(cols), "accuracy": acc, "macro_f1": mf1})
        
    print("\n--- time-ordered split within each class (earliest 80% train, latest 20% test)")
    t = pd.to_datetime(df.loc[X.index, "frame.time"], errors="coerce", format="mixed")
    rank = t.groupby(y).rank(pct=True, method="first", na_option="bottom")
    tr = rank <= 0.8
    for k, cols in variants.items():
        acc, mf1 = fit_eval(X.loc[tr, cols].copy(), X.loc[~tr, cols].copy(), y[tr], y[~tr], k)
        results.append({"split": "time-ordered", "variant": k, "features": len(cols), "accuracy": acc, "macro_f1": mf1})

    res_df = pd.DataFrame(results)
    res_df.to_csv("ablation_results.csv", index=False)
    print("\nAblation results saved to ablation_results.csv:")
    print(res_df.to_string())
