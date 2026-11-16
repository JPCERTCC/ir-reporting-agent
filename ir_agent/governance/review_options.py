"""Labels and one-line meanings of the review decision options.

Single definition shared by the Markdown review documents (the inline YAML
comment) and the HTML review page (select labels and help text), so a first-time
reviewer sees the same wording in both. Only the wording lives here: the enum
values are unchanged, and documents generated with older option lists still
parse and render.
"""

from __future__ import annotations

OPTION_LABELS: dict[str, str] = {
    "approved": "承認",
    "edited": "文言を直して承認",
    "downgraded": "確度を下げて承認",
    "rejected": "却下",
    "needs_more_context": "保留",
    "accepted_as_limitation": "制約として報告書に書く",
    "deferred_with_reason": "追加調査として推奨対策に回す",
    "out_of_scope_with_analyst_approval": "調査対象外とする",
    # Legacy options: no longer offered in new documents (they had no effect
    # distinct from the others) but still accepted and labelled.
    "mitigated_by_claim_downgrade": "分析結果の確度を下げて解消(旧選択肢)",
    "addressed_by_additional_evidence": "追加の証拠で解消済み(旧選択肢)",
}

# What choosing the option does to the report, keyed by item type so the same
# value can be explained in the terms of the document it appears in.
OPTION_HELP: dict[str, dict[str, str]] = {
    "evidence_candidate": {
        "approved": "証拠として台帳に登録し、報告書の根拠に使います。",
        "edited": "証拠として台帳に登録します(承認と同じ扱いです)。",
        "rejected": "台帳に登録しません。報告書の根拠には使いません。",
        "needs_more_context": "今回は登録せず、判断を持ち越します。",
    },
    "claim": {
        "approved": "この文言と確度のまま報告書に載せます。",
        "edited": "「修正後の文言」に書いた文で報告書に載せます。",
        "downgraded": "文言はそのままで、「変更後の確度」に下げて載せます。",
        "rejected": "報告書に載せません。",
        "needs_more_context": "今回の報告書には載せず、判断を持ち越します。",
    },
    "gap": {
        "accepted_as_limitation": "関係する所見のそばに「確認できなかった」制約として書き、"
        "推奨対策にも挙げます。",
        "deferred_with_reason": "本文の制約には書かず、推奨対策(追加調査・ログ取得)"
        "にだけ挙げます。",
        "out_of_scope_with_analyst_approval": "今回の調査範囲外として、報告書には書きません。",
        "needs_more_context": "判断を持ち越します(推奨対策の候補には残ります)。",
    },
}

# Options offered in newly generated documents, in display order.
EVIDENCE_OPTIONS = ["approved", "rejected", "needs_more_context"]
CLAIM_OPTIONS = ["approved", "edited", "downgraded", "rejected", "needs_more_context"]
GAP_OPTIONS = [
    "accepted_as_limitation",
    "deferred_with_reason",
    "out_of_scope_with_analyst_approval",
    "needs_more_context",
]


def option_comment(options: list[str], review_language: str = "ja") -> str:
    """Inline YAML comment listing the options, e.g. ``approved: 承認 | ...``.

    The ``value: label`` form is what the HTML page parses the choices from.
    """
    if review_language != "ja":
        return " | ".join(options)
    return " | ".join(f"{o}: {OPTION_LABELS[o]}" for o in options)
