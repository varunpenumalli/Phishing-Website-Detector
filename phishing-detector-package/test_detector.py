from phishing_detector import PhishingDetector
import pandas as pd          # ← NEW
from pathlib import Path 


def simple_test():
    ...
    #  (your whole simple_test function remains exactly the same)
    ...

# ───────────────── dataset test (CSV) ───────────────── #
def dataset_test(csv_path: str = "PhiUSIIL_Phishing_URL_Dataset.csv",
                 threshold: int = 6):
    """
    Evaluate PhishingDetector on the full dataset.
    0 = phishing, 1 = legitimate  (per your description)
    """
    if not Path(csv_path).exists():
        print(f"⚠️  CSV not found: {csv_path}")
        return

    df = pd.read_csv(csv_path)
    if not {'url', 'label'}.issubset(df.columns):
        print("⚠️  CSV must have 'url' and 'label' columns")
        return

    detector = PhishingDetector()
    df['score'] = df['url'].apply(lambda u: detector.analyze_url(str(u))['score'])
    # map score → predicted label (0 = phish, 1 = legit)
    df['pred'] = df['score'].apply(lambda s: 0 if s >= threshold else 1)

    tp = ((df.label == 0) & (df.pred == 0)).sum()
    tn = ((df.label == 1) & (df.pred == 1)).sum()
    fp = ((df.label == 1) & (df.pred == 0)).sum()
    fn = ((df.label == 0) & (df.pred == 1)).sum()
    total = len(df)

    print("\n📂 DATASET TEST")
    print("=" * 50)
    print(f"Rows analysed : {total}")
    print(f"Threshold     : ≥{threshold} points ⇒ phishing")
    print(f"Accuracy      : {(tp+tn)/total*100:.2f}%")
    print(f"False Positives (legit→phish) : {fp}")
    print(f"False Negatives (phish missed): {fn}")
    if tp+fn:
        print(f"Recall  (Phish detection rate) : {tp/(tp+fn)*100:.2f}%")
    if tn+fp:
        print(f"Specificity (Legit pass rate)  : {tn/(tn+fp)*100:.2f}%")
    if tp+fp:
        print(f"Precision (When flagged, really phish) : {tp/(tp+fp)*100:.2f}%")

# ───────────────── run both when executed directly ───────────────── #
if __name__ == "__main__":
    simple_test()          # your 16‑URL sanity check
    dataset_test()         # full CSV evaluation (same directory)
