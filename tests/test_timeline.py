"""Sparse timeline regression checks across long telemetry gaps."""
import unittest
import pandas as pd
from modules.live_ui import timeline_counts


class TimelineTests(unittest.TestCase):
    def test_minute_counts_skip_gaps_and_preserve_all_valid_events(self):
        timestamps = pd.Series(["2026-10-01T10:00:01Z", "2026-10-01T10:00:59Z",
                                "2026-11-17T10:02:00Z", "invalid", None])
        result = timeline_counts(timestamps, "Minute")
        self.assertEqual(result["Events"].tolist(), [2, 1])
        self.assertEqual(str(result["Timestamp"].dt.tz), "UTC")
        self.assertTrue(result["Timestamp"].is_monotonic_increasing)

    def test_hour_counts_normalize_offsets(self):
        result = timeline_counts(pd.Series(["2026-11-17T10:01:00+00:00",
                                           "2026-11-17T11:45:00+01:00"]), "Hour")
        self.assertEqual(result["Events"].tolist(), [2])

    def test_century_gap_does_not_expand_output(self):
        result = timeline_counts(pd.Series(["2000-01-01", "2100-01-01"]), "Minute")
        self.assertEqual(len(result), 2)
        self.assertEqual(result["Events"].sum(), 2)

    def test_invalid_and_empty_timestamps(self):
        for timestamps in [pd.Series([], dtype="object"), pd.Series([None, "invalid"])]:
            self.assertTrue(timeline_counts(timestamps, "Minute").empty)
