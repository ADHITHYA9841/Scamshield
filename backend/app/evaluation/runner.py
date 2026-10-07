import json
import os
from typing import Dict, Any, List
from app.engines.rule_engine import RuleEngine
from app.engines.url_engine import URLEngine
from app.engines.qr_engine import QREngine
from app.engines.phone_engine import PhoneEngine
from app.engines.llm_engine import LLMEngine
from app.engines.score_fusion import ScoreFusionEngine

DATASET_PATH = os.path.join(os.path.dirname(__file__), "../../../dataset/benchmark.json")


def calculate_metrics(y_true: List[str], y_pred: List[str]) -> Dict[str, Any]:
    """Calculates classification metrics considering 'scam' and 'suspicious' as positive detections."""
    tp = 0
    fp = 0
    tn = 0
    fn = 0

    for true_label, pred_label in zip(y_true, y_pred):
        is_true_positive = true_label in ("scam", "suspicious")
        is_pred_positive = pred_label in ("SCAM", "SUSPICIOUS")

        if is_true_positive and is_pred_positive:
            tp += 1
        elif not is_true_positive and is_pred_positive:
            fp += 1
        elif not is_true_positive and not is_pred_positive:
            tn += 1
        else:
            fn += 1

    total = tp + fp + tn + fn
    acc = (tp + tn) / total if total > 0 else 0.0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (tp + fn) if (tp + fn) > 0 else 0.0

    return {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "counts": {"TP": tp, "FP": fp, "TN": tn, "FN": fn, "total": total}
    }


def run_evaluation() -> Dict[str, Any]:
    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(f"Evaluation dataset not found at {DATASET_PATH}")

    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        samples = json.load(f)

    rule_eng = RuleEngine()
    url_eng = URLEngine()
    qr_eng = QREngine()
    phone_eng = PhoneEngine()
    llm_eng = LLMEngine()
    fusion_eng = ScoreFusionEngine()

    ground_truth = []
    rules_preds = []
    llm_preds = []
    hybrid_preds = []

    by_lang: Dict[str, Dict[str, List[str]]] = {}
    by_type: Dict[str, Dict[str, List[str]]] = {}

    for sample in samples:
        content = sample["input"]
        itype = sample["input_type"]
        lang = sample["language"]
        true_label = sample["label"]

        ground_truth.append(true_label)

        # Baseline 1: Rules-only
        r_score, r_ev, _ = rule_eng.analyze(content)
        r_pred = "SCAM" if r_score >= 70 else ("SUSPICIOUS" if r_score >= 30 else "SAFE")
        rules_preds.append(r_pred)

        # Baseline 2: LLM-only
        llm_data = llm_eng.analyze(content)
        llm_score = float(llm_data.get("semantic_risk_score", 0.0))
        l_pred = "SCAM" if llm_score >= 70 else ("SUSPICIOUS" if llm_score >= 30 else "SAFE")
        llm_preds.append(l_pred)

        # Hybrid ScamShield (Full Fusion)
        url_score = 0.0
        url_ev = []
        qr_score = 0.0
        qr_ev = []
        phone_score = 0.0
        phone_ev = []
        details = {}

        if itype == "url":
            url_score, url_ev, details = url_eng.analyze(content, skip_live_vt=True)
        elif itype == "qr":
            qr_score, qr_ev, details = qr_eng.analyze(content)
        elif itype == "phone":
            phone_score, phone_ev, details = phone_eng.analyze(content)
        elif itype == "text":
            extracted_urls = url_eng.extract_urls(content)
            details = {"extracted_urls_count": len(extracted_urls)}
            for u in extracted_urls[:3]:
                u_score, u_ev, _ = url_eng.analyze(u, skip_live_vt=True)
                if u_score > url_score:
                    url_score = u_score
                url_ev.extend(u_ev)

        hybrid_res = fusion_eng.fuse(
            input_type=itype,
            detected_language=lang,
            rule_score=r_score,
            rule_evidence=r_ev,
            url_score=url_score,
            url_evidence=url_ev,
            llm_score=llm_score,
            llm_data=llm_data,
            qr_score=qr_score,
            qr_evidence=qr_ev,
            phone_score=phone_score,
            phone_evidence=phone_ev,
            engine_details=details
        )
        h_pred = hybrid_res.verdict
        hybrid_preds.append(h_pred)

        # Group by language & input type
        by_lang.setdefault(lang, {"true": [], "hybrid": []})
        by_lang[lang]["true"].append(true_label)
        by_lang[lang]["hybrid"].append(h_pred)

        by_type.setdefault(itype, {"true": [], "hybrid": []})
        by_type[itype]["true"].append(true_label)
        by_type[itype]["hybrid"].append(h_pred)

    overall_rules = calculate_metrics(ground_truth, rules_preds)
    overall_llm = calculate_metrics(ground_truth, llm_preds)
    overall_hybrid = calculate_metrics(ground_truth, hybrid_preds)

    lang_metrics = {l: calculate_metrics(data["true"], data["hybrid"]) for l, data in by_lang.items()}
    type_metrics = {t: calculate_metrics(data["true"], data["hybrid"]) for t, data in by_type.items()}

    results = {
        "dataset_size": len(samples),
        "baselines": {
            "rules_only": overall_rules,
            "llm_only": overall_llm,
            "hybrid_scamshield": overall_hybrid
        },
        "by_language": lang_metrics,
        "by_input_type": type_metrics
    }

    # Print clean summary
    print("\n=================== SCAMSHIELD BENCHMARK EVALUATION ===================")
    print(f"Total Samples: {len(samples)}")
    print(f"{'Engine':<20} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'FPR':<8}")
    print("-" * 75)
    for name, m in [("Rules-Only", overall_rules), ("LLM-Only", overall_llm), ("Hybrid ScamShield", overall_hybrid)]:
        print(f"{name:<20} | {m['accuracy']:<10.4f} | {m['precision']:<10.4f} | {m['recall']:<10.4f} | {m['f1_score']:<10.4f} | {m['false_positive_rate']:<8.4f}")
    print("=======================================================================\n")

    return results


if __name__ == "__main__":
    run_evaluation()
