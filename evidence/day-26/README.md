# Day 26 — PII Detection and Masking

This checkpoint records one predeclared offline comparison over 24 labeled synthetic cases. Raw
fixture text, detected spans, and masked output remain under ignored `evidence/raw/day-26/`; this
directory contains only reviewed counts, versions, hashes, and interpretation limits.

## Registered question

The experiment asks how four paths behave on the same labeled text: no masking, exact
application-owned rules, Presidio's built-in recognizers, and Presidio plus every application rule.
It measures exact entity spans and whether an expected synthetic value remains visible after
masking. Detection never grants resource access or repairs an authorization failure.

## Fixed contract

- Runner commit: `3013add`
- Presidio Analyzer / Anonymizer: `2.2.364 / 2.2.364`
- NLP model: `en_core_web_sm==3.8.0`
- Cases: `24` (`12` positive, `12` negative)
- Expected entity spans: `16`
- Profiles / path evaluations: `4 / 96`
- Raw SHA-256: `87c10813ebb5eb6eb6db6a3e0b8a9a930dadd08a53034f9385fbc61eb2eaba61`
- Cases SHA-256: `b97c50cdd90a86e82308da3f74755bbb21acef0a86c3e7b6ad17b35a25237666`
- Policy SHA-256: `44688b339af95b0f1aca0fe5341050f02c7cb71afc2c502367ee2cd90058cb75`
- Recorded: `2026-08-25T04:02:45.839320Z`

The raw file is intentionally not committed.

## Results

| Profile | TP | FP | FN | Precision | Recall | Unmasked expected values | Changed negative cases |
|---|---:|---:|---:|---:|---:|---:|---:|
| Raw | 0 | 0 | 16 | N/A | 0.0000 | 16 | 0 |
| Application rules | 12 | 0 | 4 | 1.0000 | 0.7500 | 4 | 0 |
| Presidio built-in | 5 | 0 | 11 | 1.0000 | 0.3125 | 11 | 0 |
| Layered | 12 | 0 | 4 | 1.0000 | 0.7500 | 4 | 0 |

The application rules detected the experiment's exact email, Taiwan-style phone, Luhn-valid test
card, and customer-ID shapes. They intentionally had no person-name recognizer. Presidio's built-in
profile detected five labeled spans in this small English corpus. Adding all application rules to
the Presidio registry recovered the deterministic spans but did not recover the four missed person
spans, so the layered profile tied the application rules instead of exceeding them.

All registered prediction checks passed. No profile changed a negative case in this fixture set,
but that zero is only a property of these 12 negatives.

## Interpretation limits

This is a 24-case English-language synthetic benchmark with exact span labels. It does not measure
Chinese name recognition, address formats, free-form identifiers, adversarial obfuscation, image
PII, or production traffic. Precision `1.0` means no false positives appeared in this fixed set; it
does not predict production precision. The built-in result depends on the locked Presidio and
SpaCy versions and is not a general Presidio benchmark.

Masking reduces the values visible in one text path. It does not decide whether collection was
lawful, whether the current user may access a record, whether a reversible token is safe, or whether
the original value already entered another prompt, trace, cache, or log. The runner used only
committed synthetic fixtures and made `0` model calls, `0` network calls, and `0` external side
effects.
