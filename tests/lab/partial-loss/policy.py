"""Lab-only paired UDP loss decision. Input is chronological paired observations."""
import json
import math
import sys


def evaluate(rows, current, window=3600):
    """Compare paired UDP outcomes inside the time window and return the selected exit and reason."""
    if current not in ("fi1", "fi2") or not rows or window <= 0:
        raise ValueError("need a current FI interface, positive window and observations")
    now = rows[-1]["ts"]
    if any(not math.isfinite(r["ts"]) or type(r["fi1"]) is not bool or type(r["fi2"]) is not bool for r in rows):
        raise ValueError("invalid observation")
    if any(a["ts"] >= b["ts"] for a,b in zip(rows,rows[1:])):
        raise ValueError("observations must have strictly increasing paired timestamps")
    observations = [r for r in rows if now-window < r["ts"] <= now]
    n = len(observations)
    losses = {i:sum(not r[i] for r in observations) for i in ("fi1","fi2")}
    alt = "fi2" if current == "fi1" else "fi1"
    wins = sum(r[alt] and not r[current] for r in observations)
    defeats = sum(r[current] and not r[alt] for r in observations)
    d = wins + defeats
    # Two-sided exact sign test on discordant pairs (descriptive under serial dependence).
    p = min(1., 2 * sum(math.comb(d,i) for i in range(min(wins,defeats)+1)) / (1 << d))
    reason = ("insufficient_pairs" if n < 100 else "hold_no_advantage" if wins <= defeats
              else "hold_margin" if (wins-defeats)*100 < 5*n or wins-defeats < 5
              else "hold_confidence" if p > .05 else "better_delivery")
    return dict(selected=alt if reason=="better_delivery" else current, reason=reason, pairs=n,
                losses=losses, paired_p=p, window_s=window, ts=now)


if __name__=="__main__":
    with open(sys.argv[1]) as f:
        print(json.dumps(evaluate([json.loads(l) for l in f],sys.argv[2])))
