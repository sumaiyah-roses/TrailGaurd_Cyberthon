"""Per-user baseline with smoothed surprise scoring (-log2 of smoothed frequency)."""
import math
from collections import Counter


class Baseline:
    def __init__(self, alpha=0.5):
        self.a, self.n = alpha, 0
        self.dev, self.cty, self.asn = Counter(), Counter(), Counter()
        self.hours = [0] * 24

    def _bits(self, counter, key):
        p = (counter[key] + self.a) / (self.n + self.a * (len(counter) + 1))  # +1 slot for "unseen"
        return -math.log2(p)

    def _hour_bits(self, h):
        c = self.hours  # neighbouring hours share mass: 23:00 and 00:00 are similar
        s = c[h] + 0.5 * (c[(h - 1) % 24] + c[(h + 1) % 24])
        return -math.log2((s + self.a) / (2 * self.n + 24 * self.a))

    def surprise(self, row):
        return {"device": self._bits(self.dev, row.device_id), "country": self._bits(self.cty, row.country),
                "asn": self._bits(self.asn, row.asn), "hour": self._hour_bits(row.timestamp.hour)}

    def update(self, row):
        self.n += 1
        self.dev[row.device_id] += 1
        self.cty[row.country] += 1
        self.asn[row.asn] += 1
        self.hours[row.timestamp.hour] += 1
