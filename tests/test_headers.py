import unittest
import random
from typing import List

import yasha

def capsicum(s: str, n: int = 10) -> List[str]:
    if not s:
        return [""]
    
    indices = list(range(len(s)))
    results = []

    for _ in range(n):
        to_capitalise = random.sample(indices, random.choice(indices))
        results.append(''.join([x.upper() if i in to_capitalise else x for i, x in enumerate(s)]))
    
    return results

class TestHeaders(unittest.TestCase):
    def test_hsts_checks(self):
        checks_and_results = {
            "Strict-Transport-Security: max-age=31536000; includeSubDomains": ["pass"],
            "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload": ["pass"],
            "" : ['fail', 'No HSTS header found'],
            "Strict-Transport-Security: max-age=31535999; includeSubDomains": ['fail', 'max-age set to 31535999'],
            "Strict-Transport-Security: includeSubDomains": ['fail', 'HSTS does not contain max age'],
        }
        for check in checks_and_results.keys():
            result = yasha.hsts_check([check])
            self.assertEqual(result, checks_and_results[check])

            for case in capsicum(check):
                with self.subTest(case=case):
                    self.assertEqual(result, yasha.hsts_check([case]))

    def test_xframeoptions_check(self):
        checks_and_results = {
            "X-Frame-Options: DENY": ['pass'],
            "X-Frame-Options: SAMEORIGIN": ['pass'],
            "X-Frame-Options: QUACKQUACK": ['fail', 'X-Frame-Options value is QUACKQUACK'],
        }
        for check in checks_and_results.keys():
            result = yasha.xframeoptions_check([check])
            self.assertEqual(result, checks_and_results[check])

            for case in capsicum(check):
                with self.subTest(case=case):
                    self.assertEqual(list(map(lambda x: x.lower(), result)), list(map(lambda x: x.lower(), yasha.xframeoptions_check([case]))))


if __name__ == '__main__':
    unittest.main()