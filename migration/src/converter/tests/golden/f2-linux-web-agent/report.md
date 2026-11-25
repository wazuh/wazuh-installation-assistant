# Migration report

Status: candidate_requires_lab_validation.

Candidate files are incomplete while decisions remain. No runtime validation was run.

All input values are masked, including unknown values. Generated configs retain required secrets; protect them.

| Option id | Classification | Guide section | Action left to user |
|---|---|---|---|
| f2-linux-web-agent.conf:/agent_config[1]/labels[1]/label[1]/@key | dropped_without_replacement | manager-4x-to-5x.md#groups | Remove ignored block; no direct replacement. For labels, review group membership (wazuh.agent.groups) as an alternative event key. |
| f2-linux-web-agent.conf:/agent_config[1]/labels[1]/label[1] | dropped_without_replacement | manager-4x-to-5x.md#groups | Remove ignored block; no direct replacement. For labels, review group membership (wazuh.agent.groups) as an alternative event key. |
| f2-linux-web-agent.conf:/agent_config[1]/localfile[1]/log_format[1] | carried_as_is | manager-4x-to-5x.md#groups | Preserve exact bytes; this is an evidenced surviving setting, not a full schema check. |
| f2-linux-web-agent.conf:/agent_config[1]/localfile[1]/location[1] | carried_as_is | manager-4x-to-5x.md#groups | Preserve exact bytes; this is an evidenced surviving setting, not a full schema check. |
| f2-linux-web-agent.conf:/agent_config[1]/localfile[2]/log_format[1] | carried_as_is | manager-4x-to-5x.md#groups | Preserve exact bytes; this is an evidenced surviving setting, not a full schema check. |
| f2-linux-web-agent.conf:/agent_config[1]/localfile[2]/location[1] | carried_as_is | manager-4x-to-5x.md#groups | Preserve exact bytes; this is an evidenced surviving setting, not a full schema check. |
| f2-linux-web-agent.conf:/agent_config[1]/syscheck[1]/directories[1]/@check_all | carried_as_is | manager-4x-to-5x.md#groups | Preserved byte for byte; validate selection/attribute on target agents. |
| f2-linux-web-agent.conf:/agent_config[1]/syscheck[1]/directories[1]/@realtime | carried_as_is | manager-4x-to-5x.md#groups | Preserved byte for byte; validate selection/attribute on target agents. |
| f2-linux-web-agent.conf:/agent_config[1]/syscheck[1]/directories[1] | carried_as_is | manager-4x-to-5x.md#groups | Preserve exact bytes; this is an evidenced surviving setting, not a full schema check. |
