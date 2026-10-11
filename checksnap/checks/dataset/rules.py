"""Rule catalog for --check-dataset. RuleInfo lives here (not in core.py) because the spec names the
dataclass but core.py does not define it; checksnap --explain and docs/RULES.md read RULES."""
from __future__ import annotations

from dataclasses import dataclass

from checksnap.core import Severity


@dataclass(frozen=True)
class RuleInfo:
    id: str
    severity: Severity
    title: str
    explanation: str
    fix_hint: str
    needs_snap: bool = False


def _r(id, sev, title, explanation, fix, snap=False):
    return id, RuleInfo(id, sev, title, explanation, fix, snap)


RULES: dict[str, RuleInfo] = dict([
    _r("DS-CONTAM-001", Severity.HIGH, "Benchmark item present in the data (Snap)",
       "Snap was asked, for batches of up to 56 benchmark items at once, whether each item appears in the data copied, reworded, "
       "translated or as solution only. A score is the model's probability for the whole window, not proof: the report lists the "
       "window range, 13-gram corroboration and, when localisation worked, a ~2 KB snippet. HIGH when score >= 0.8, MEDIUM otherwise. "
       "--contam-mode prefiltered only sends records sharing several rare words with some item; that drops paraphrases that share few "
       "words, and its recall loss has not been measured on real data yet, so exhaustive is the default.",
       "Read the snippet. If real, remove the matching records from the training data and retrain or re-evaluate.", True),
    _r("DS-CONTAM-002", Severity.HIGH, "Benchmark n-gram overlap with the data",
       "Local check. An item is flagged when its whole text, a 13-gram or an 8-gram also occurs in a dataset record (lower-cased word "
       "tokens). Exact or half the 13-grams matching is HIGH, any 13-gram MEDIUM, 8-gram only LOW. Items shorter than 8 words (13 for "
       "the 13-gram test) are blind to n-gram matching and are counted separately.",
       "Deduplicate the training data against the benchmark and drop the matching records."),
    _r("DS-DUP-001", Severity.MEDIUM, "Exact duplicate records",
       "Records whose normalised text (lower-case word tokens) is identical. Duplicates over-weight some examples and inflate "
       "memorisation and eval scores when they straddle splits.", "Keep one copy of each."),
    _r("DS-DUP-002", Severity.LOW, "Near-duplicate records",
       "Records with estimated word-3-shingle Jaccard similarity >= --dup-threshold, found with MinHash (64 permutations) and LSH "
       "buckets. The similarity is an estimate (about +-0.06).", "Review clusters; keep one representative."),
    _r("DS-LEAK-001", Severity.HIGH, "Eval record present exactly in the dataset",
       "A record of --eval has identical normalised text to a dataset record, so eval scores are inflated.", "Remove it from one split."),
    _r("DS-LEAK-002", Severity.MEDIUM, "Eval record is a near-duplicate of a dataset record",
       "Estimated Jaccard >= --dup-threshold between an eval record and a dataset record.", "Remove or re-split."),
    _r("DS-LEAK-003", Severity.MEDIUM, "Same ids in dataset and eval",
       "--id-field values or --id-regex matches on file names occur in both splits (for example the same video or channel).",
       "Split by id (group split), not by record."),
    _r("DS-PII-001", Severity.HIGH, "Personal data or secrets in records",
       "Emails, phone numbers, IBANs and credit cards (checksum validated), government-id-like numbers (US SSN, Turkish TC kimlik "
       "with checksum), public IPv4 addresses, API keys, private keys and tokens. Matches are masked: first 4 characters plus length. "
       "Severity: secrets HIGH, financial/government ids MEDIUM, email/phone/IP LOW.", "Redact or drop the records; rotate leaked secrets."),
    _r("DS-HYG-001", Severity.LOW, "Empty or NaN fields", "Fields that are null, blank, or the strings nan/null/none.", "Fill or drop."),
    _r("DS-HYG-002", Severity.LOW, "Inconsistent keys across records",
       "Some records have a different key set than the most common one.", "Normalise the schema."),
    _r("DS-HYG-003", Severity.MEDIUM, "Duplicate ids", "The same --id-field value appears on several records.", "Make ids unique or merge."),
    _r("DS-HYG-004", Severity.LOW, "Length outliers",
       "Records longer than Q3 + 3*IQR (or shorter than Q1 - 3*IQR) in characters. Needs >= 20 records.", "Inspect; truncate or drop."),
    _r("DS-HYG-005", Severity.MEDIUM, "Mojibake or encoding errors",
       "Text contains U+FFFD or typical UTF-8-read-as-Latin-1 sequences (Ã©, â€™).", "Re-decode the source with the right encoding."),
    _r("DS-HYG-006", Severity.LOW, "Label imbalance",
       "With --label-field: majority class above 90% or largest/smallest class ratio >= 10.", "Rebalance or use class weights."),
    _r("DS-HYG-007", Severity.MEDIUM, "Label shift between dataset and eval",
       "Total variation distance of the label distributions >= 0.15, or classes present in only one split.", "Stratify the split."),
    _r("DS-HYG-008", Severity.MEDIUM, "Truncated records",
       "Unparsable JSONL lines (typically a cut-off file) or >= 10 records (and >= 5%) with exactly the maximal length of >= 128 chars (a hard truncation limit).",
       "Re-export the data; check the truncation limit."),
    _r("DS-HYG-009", Severity.LOW, "Mixed languages or scripts",
       "A second script/language (stop-word heuristic for Latin text, script ranges otherwise) covers >= 5% of classified records.",
       "Confirm the mix is intended or filter."),
    _r("DS-LIC-001", Severity.MEDIUM, "Licence not allowed or restrictive licence text",
       "Metadata licence/source not in --allowed-licenses, restrictive wording found by a local pattern, or (Snap) a sampled window "
       "that states a non-commercial, no-derivatives or all-rights-reserved licence.", "Check the source terms before training or release.", True),
    _r("DS-IMG-001", Severity.LOW, "Near-duplicate images",
       "dHash (9x8 grayscale) Hamming distance <= 4 between images of the dataset.", "Keep one per cluster.", False),
    _r("DS-IMG-002", Severity.HIGH, "Image leak between dataset and eval",
       "An eval image is a near-duplicate (dHash <= 4) of a dataset image, or --id-regex ids are shared across splits.", "Split by id."),
    _r("DS-IMG-003", Severity.MEDIUM, "Corrupt, blank or tiny images",
       "Pillow cannot decode the file, the pixel standard deviation is ~0, or a side is under 32 px.", "Remove or re-export."),
])
