import unittest
from policy import evaluate

def rows(vals, offset=0):
    """Build timestamped paired observations from a sequence of FI-1 and FI-2 delivery outcomes."""
    return [dict(ts=offset+i, fi1=a, fi2=b) for i,(a,b) in enumerate(vals)]

class PolicyTest(unittest.TestCase):
    """Exercise thresholds, history expiry and retention of the current exit on equal delivery."""
    def test_burst_stays_and_sustained_switches(self):
        """Verify that a short burst is tolerated but persistent comparative loss selects the reserve."""
        base=[(True, True)]*100
        self.assertEqual(evaluate(rows(base+[(False,True)]*3), "fi1")["selected"], "fi1")
        sustained=[(i%10!=0, True) for i in range(200)]
        self.assertEqual(evaluate(rows(base+sustained), "fi1")["selected"], "fi2")
    def test_tie_and_rolling_window(self):
        """Verify that expired losses leave equal healthy exits and the current selection is retained."""
        bad=rows([(False,True)]*100)
        equal=rows([(True,True)]*100,3700)
        r=evaluate(bad+equal, "fi2")
        self.assertEqual((r["selected"],r["pairs"],r["losses"]["fi1"]), ("fi2",100,0))
    def test_no_evidence_without_peer(self):
        """Verify that an insufficient number of paired observations prevents a switch."""
        self.assertEqual(evaluate(rows([(False,True)]*10), "fi1")["reason"], "insufficient_pairs")
    def test_return_only_when_better(self):
        """Verify that the primary is reselected when the reserve's measured loss is worse."""
        self.assertEqual(evaluate(rows([(True,i%10!=0) for i in range(100)]), "fi2")["selected"], "fi1")
