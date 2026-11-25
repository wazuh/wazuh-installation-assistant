# Migration report

Status: candidate_requires_lab_validation.

Candidate files are incomplete while decisions remain. No runtime validation was run.

All input values are masked, including unknown values. Generated configs retain required secrets; protect them.

| Option id | Classification | Guide section | Action left to user |
|---|---|---|---|
| f1a-linux-servers-agent.conf:/agent_config[1]/localfile[1]/log_format[1] | carried_as_is | manager-4x-to-5x.md#groups | Preserve exact bytes; this is an evidenced surviving setting, not a full schema check. |
| f1a-linux-servers-agent.conf:/agent_config[1]/localfile[1]/location[1] | carried_as_is | manager-4x-to-5x.md#groups | Preserve exact bytes; this is an evidenced surviving setting, not a full schema check. |
| f1a-linux-servers-agent.conf:/agent_config[1]/sca[1]/policies[1]/policy[1] | carried_as_is | manager-4x-to-5x.md#groups | Preserve exact bytes; this is an evidenced surviving setting, not a full schema check. |
