# Experiment results

Rows: 960. Instrument: commit `d48a7cf3aff2bf634d99c02bde1339f9356a6c41`.

## Measurement quality
| constrained | n | parsed_rate | no_commit_rate |
|---|---|---|---|
| False | 480.0 | 1.0 | 0.225 |
| True | 480.0 | 1.0 | 0.0 |

## LLM level, by payload class
| payload_class | n | full_suppression | drift | no_commit | mean_sev_shift |
|---|---|---|---|---|---|
| context-manipulation | 192.0 | 0.354 | 0.677 | 0.12 | -1.224 |
| direct-override | 192.0 | 0.005 | 0.333 | 0.135 | 0.329 |
| obfuscated | 192.0 | 0.094 | 0.49 | 0.083 | -0.02 |
| split-payload | 192.0 | 0.12 | 0.333 | 0.109 | -0.427 |

## LLM level, by scenario
| pair_id | n | full_suppression | drift | no_commit | mean_sev_shift |
|---|---|---|---|---|---|
| ddos_marginal | 192.0 | 0.193 | 0.484 | 0.073 | -0.247 |
| ddos_strong | 192.0 | 0.177 | 0.448 | 0.141 | -0.921 |
| scan_marginal | 192.0 | 0.094 | 0.453 | 0.109 | 0.052 |
| scan_strong | 192.0 | 0.109 | 0.448 | 0.125 | -0.25 |

## LLM level, by safeguard condition
| warn_untrusted | separate_untrusted | constrained | n | full_suppression | drift | no_commit | mean_sev_shift |
|---|---|---|---|---|---|---|---|
| False | False | False | 96.0 | 0.052 | 0.323 | 0.167 | -0.037 |
| False | False | True | 96.0 | 0.385 | 0.667 | 0.0 | -1.104 |
| False | True | False | 96.0 | 0.0 | 0.5 | 0.323 | 0.028 |
| False | True | True | 96.0 | 0.281 | 0.354 | 0.0 | -0.573 |
| True | False | False | 96.0 | 0.01 | 0.583 | 0.26 | 0.063 |
| True | False | True | 96.0 | 0.094 | 0.458 | 0.0 | -0.01 |
| True | True | False | 96.0 | 0.021 | 0.448 | 0.146 | -0.005 |
| True | True | True | 96.0 | 0.302 | 0.333 | 0.0 | -0.729 |

## LLM level, undefended baseline (all three safeguards off)
| payload_class | n | full_suppression | drift | no_commit | mean_sev_shift |
|---|---|---|---|---|---|
| context-manipulation | 24.0 | 0.0 | 0.375 | 0.208 | 0.175 |
| direct-override | 24.0 | 0.0 | 0.083 | 0.083 | -0.045 |
| obfuscated | 24.0 | 0.208 | 0.625 | 0.167 | -0.225 |
| split-payload | 24.0 | 0.0 | 0.208 | 0.208 | -0.044 |

## System level, accepted downgrades
*Constrained rows only. An accepted downgrade is a recommendation the attacker made less severe that the validator then accepted. The policy may permit the softer action, so this measures residual attacker influence, not a policy violation.*

| payload_class | n | llm_downgraded | full_suppression | accepted_downgrade |
|---|---|---|---|---|
| context-manipulation | 96.0 | 0.833 | 0.708 | 0.031 |
| direct-override | 96.0 | 0.115 | 0.01 | 0.073 |
| obfuscated | 96.0 | 0.302 | 0.104 | 0.146 |
| split-payload | 96.0 | 0.438 | 0.24 | 0.083 |

Mean severity shift among accepted downgrades: -1.083

## System level, clean-input rejection
*Clean incidents, constrained rows. Which rule refused a recommendation produced without any injection. Not a false positive rate: clean means uninjected, not correct.*

|  | rejections |
|---|---|
| severity_floor | 23 |
| target_ip | 0 |
| duration | 2 |
| isolate_policy | 0 |

Clean constrained recommendations: 96. Refused: 23 (0.240).
