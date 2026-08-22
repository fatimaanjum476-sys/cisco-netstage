"""
app.py
-------
NetSage AI — Operations Dashboard.

A human-in-the-loop dashboard: pick a lab case, see the diagnosis
(rule engine or AI), and approve / edit / reject it. Every decision
is logged so the class can see how often the AI was right.

Run with:  streamlit run src/app.py
"""

import csv
import datetime as dt
from pathlib import Path

import pandas as pd
import streamlit as st

from engine import diagnose

BASE_DIR = Path(__file__).resolve().parent
CASES_PATH = BASE_DIR / "cases.csv"
AUDIT_LOG_PATH = BASE_DIR / "audit_log.csv"

AUDIT_FIELDS = [
    "timestamp", "case_id", "source", "rule_name", "root_cause",
    "confidence", "decision", "operator_note",
]


def load_cases() -> pd.DataFrame:
    return pd.read_csv(CASES_PATH)


def load_audit_log() -> pd.DataFrame:
    if AUDIT_LOG_PATH.exists():
        return pd.read_csv(AUDIT_LOG_PATH)
    return pd.DataFrame(columns=AUDIT_FIELDS)


def log_decision(case_id, diagnosis, decision, operator_note=""):
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    write_header = not AUDIT_LOG_PATH.exists()
    with open(AUDIT_LOG_PATH, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=AUDIT_FIELDS)
        if write_header:
            writer.writeheader()
        writer.writerow({
            "timestamp": dt.datetime.now().isoformat(timespec="seconds"),
            "case_id": case_id,
            "source": diagnosis.get("source", "unknown"),
            "rule_name": diagnosis.get("rule_name", ""),
            "root_cause": diagnosis.get("root_cause", ""),
            "confidence": diagnosis.get("confidence", ""),
            "decision": decision,
            "operator_note": operator_note,
        })


st.set_page_config(page_title="NetSage AI", page_icon="🛠️", layout="wide")
st.title("🛠️ NetSage AI — Network Diagnostic Dashboard")
st.caption(
    "Pick a case → see what's wrong → review the evidence → approve, edit, or reject the fix. "
    "Nothing is ever pushed to a device without a human clicking a button."
)

cases_df = load_cases()

tab_diagnose, tab_summary = st.tabs(["🔍 Diagnose a case", "📊 Summary & audit log"])

with tab_diagnose:
    col_pick, col_result = st.columns([1, 1.4])

    with col_pick:
        case_id = st.selectbox("Choose a case", cases_df["case_id"])
        case_row = cases_df.loc[cases_df["case_id"] == case_id].iloc[0].to_dict()

        st.markdown("**Symptom**")
        st.info(case_row["symptom"])
        st.markdown("**Topology note**")
        st.write(case_row["topology_note"])
        st.markdown("**show command output**")
        st.code(case_row["show_outputs"], language="text")

        run_clicked = st.button("▶ Run diagnosis", type="primary", use_container_width=True)

    with col_result:
        if run_clicked:
            st.session_state["diagnosis"] = diagnose(case_row)
            st.session_state["diagnosed_case_id"] = case_id

        diagnosis = st.session_state.get("diagnosis")
        shown_case_id = st.session_state.get("diagnosed_case_id")

        if diagnosis and shown_case_id == case_id:
            source_label = {
                "rule_engine": "✅ Deterministic rule engine",
                "ai_model": "🤖 AI model (rules found nothing certain)",
                "ai_unavailable": "⚠️ AI unavailable",
                "ai_error": "⚠️ AI call failed",
            }.get(diagnosis.get("source"), diagnosis.get("source", "unknown"))

            st.markdown(f"**Diagnosis source:** {source_label}")
            st.markdown(f"**Root cause:** {diagnosis.get('root_cause')}")
            c1, c2 = st.columns(2)
            c1.metric("OSI layer", diagnosis.get("osi_layer", "—"))
            c2.metric("Confidence", diagnosis.get("confidence", "—"))
            st.markdown("**Evidence**")
            st.code(diagnosis.get("evidence", ""), language="text")
            st.markdown("**Next command to confirm**")
            st.code(diagnosis.get("next_command", ""), language="text")
            fix_steps = diagnosis.get("fix_steps") or []
            if fix_steps:
                st.markdown("**Proposed fix**")
                st.code("\n".join(fix_steps), language="text")

            st.divider()
            note = st.text_input("Operator note (optional)", key=f"note_{case_id}")
            b1, b2, b3 = st.columns(3)
            if b1.button("✅ Approve & Deploy", use_container_width=True):
                log_decision(case_id, diagnosis, "Approved", note)
                st.success("Logged as Approved.")
            if b2.button("✏️ Edit Commands", use_container_width=True):
                log_decision(case_id, diagnosis, "Edited", note)
                st.warning("Logged as Edited — remember to note what you changed above.")
            if b3.button("❌ Reject", use_container_width=True):
                log_decision(case_id, diagnosis, "Rejected", note)
                st.error("Logged as Rejected (flagged as a possible false positive).")
        else:
            st.write("Run a diagnosis to see results here.")

with tab_summary:
    st.subheader("Cases by issue type")
    st.bar_chart(cases_df["concept_tag"].value_counts())

    st.subheader("Cases by OSI layer")
    st.bar_chart(cases_df["osi_layer"].value_counts())

    st.subheader("Human review log")
    audit_df = load_audit_log()
    if audit_df.empty:
        st.write("No decisions logged yet — diagnose and review a case first.")
    else:
        st.dataframe(audit_df, use_container_width=True)
        st.subheader("Decisions by type")
        st.bar_chart(audit_df["decision"].value_counts())
        st.subheader("Diagnosis source split")
        st.bar_chart(audit_df["source"].value_counts())
