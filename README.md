# NetSage AI

A simple troubleshooting helper for Cisco-style lab networks. You pick a broken
lab case, and it tells you what's probably wrong, why, and what command would
fix it — but it never touches the router or switch by itself. A person always
has to click Approve before anything is treated as "the fix."

## Why this exists

New network engineers usually know the individual commands, but connecting a
symptom ("PC can't reach the server") to the actual root cause (VLAN? DHCP?
routing? ACL? NAT?) takes experience. This tool speeds that up, while keeping
a human in charge of every decision — that's the whole point of the human
review step.

## How it actually works

1. You pick a case from a dropdown (there are 30 real lab scenarios in
   `data/cases.csv` — VLAN, DHCP, DNS, routing, ACL, NAT, wireless, etc.)
2. First, a plain Python rule checker (`src/checker.py`) looks for known,
   provable problems using pattern matching — things like "interface is
   administratively down" or "DHCP pool is full." No guessing involved.
3. If the rule checker can't find anything solid, the case gets sent to an AI
   model with a prompt that forces it to answer in a strict format (root
   cause, OSI layer, confidence, evidence, next command, fix steps).
4. Either way, you see the same result screen, and you decide: **Approve &
   Deploy**, **Edit Commands**, or **Reject**. That decision gets saved to a
   log automatically.
5. A summary tab shows how many cases came from each category, and how often
   people agreed with the diagnosis.

On the 30 bundled cases, the rule checker alone solves 24 of them (80%)
without needing the AI at all — see `docs/model_audit_log.md` for the numbers.

## Running it yourself

```bash
pip install -r requirements.txt

# optional — only needed for the 6 cases the rule checker can't solve on its own
export ANTHROPIC_API_KEY=your_key_here

streamlit run app.py
```

Open the link Streamlit prints (usually `http://localhost:8501`).

If you skip the API key, the app still works fine for every rule-based case —
it'll just tell you honestly that AI diagnosis isn't available for the 6
trickier ones, instead of making something up.

## What's in this repo

```
app.py                 the Streamlit dashboard
checker.py              deterministic rule engine
engine.py                orchestrator (rules first, then AI if needed)
cases.csv                the 30 test scenarios
system_config.json       app settings
requirements.txt         Python dependencies
diagnose_prompt.md       what we tell the AI model, with worked examples
model_audit_log.md       how to read the review log
audit_log.csv            created automatically once you review a case in the app
```

## A quick example

**Case:** PC1 can't reach Server1 in VLAN 30.
**show command says:** `GigabitEthernet0/0.10 is administratively down`

NetSage AI flags it instantly (no AI call needed — this is a hard rule):
- Root cause: sub-interface is administratively down
- Next command to confirm: `show ip interface brief`
- Suggested fix: `configure terminal` → `interface GigabitEthernet0/0.10` → `no shutdown`

The operator checks the evidence, clicks **Approve & Deploy**, and it's
logged.
