# Migration report

Status: candidate_requires_lab_validation.

Candidate files are incomplete while decisions remain. No runtime validation was run.

All input values are masked, including unknown values. Generated configs retain required secrets; protect them.

| Option id | Classification | Guide section | Action left to user |
|---|---|---|---|
| f1a-pci-scope-agent.conf:/agent_config[1]/labels[1]/label[1]/@key | dropped_without_replacement | manager-4x-to-5x.md#groups | Remove ignored block; no direct replacement. For labels, review group membership (wazuh.agent.groups) as an alternative event key. |
| f1a-pci-scope-agent.conf:/agent_config[1]/labels[1]/label[1] | dropped_without_replacement | manager-4x-to-5x.md#groups | Remove ignored block; no direct replacement. For labels, review group membership (wazuh.agent.groups) as an alternative event key. |
| f1a-pci-scope-agent.conf:/agent_config[1]/syscheck[1]/frequency[1] | carried_as_is | manager-4x-to-5x.md#groups | Preserve exact bytes; this is an evidenced surviving setting, not a full schema check. |
| f1a-pci-scope-agent.conf:/agent_config[2]/@os | carried_as_is | manager-4x-to-5x.md#groups | Preserved byte for byte; validate selection/attribute on target agents. |
| f1a-pci-scope-agent.conf:/agent_config[2]/syscheck[1]/directories[1]/@check_all | carried_as_is | manager-4x-to-5x.md#groups | Preserved byte for byte; validate selection/attribute on target agents. |
| f1a-pci-scope-agent.conf:/agent_config[2]/syscheck[1]/directories[1]/@realtime | carried_as_is | manager-4x-to-5x.md#groups | Preserved byte for byte; validate selection/attribute on target agents. |
| f1a-pci-scope-agent.conf:/agent_config[2]/syscheck[1]/directories[1] | carried_as_is | manager-4x-to-5x.md#groups | Preserve exact bytes; this is an evidenced surviving setting, not a full schema check. |
| f1a-pci-scope-agent.conf:/agent_config[3]/@os | carried_as_is | manager-4x-to-5x.md#groups | Preserved byte for byte; validate selection/attribute on target agents. |
| f1a-pci-scope-agent.conf:/agent_config[3]/syscheck[1]/directories[1]/@check_all | carried_as_is | manager-4x-to-5x.md#groups | Preserved byte for byte; validate selection/attribute on target agents. |
| f1a-pci-scope-agent.conf:/agent_config[3]/syscheck[1]/directories[1]/@realtime | carried_as_is | manager-4x-to-5x.md#groups | Preserved byte for byte; validate selection/attribute on target agents. |
| f1a-pci-scope-agent.conf:/agent_config[3]/syscheck[1]/directories[1] | carried_as_is | manager-4x-to-5x.md#groups | Preserve exact bytes; this is an evidenced surviving setting, not a full schema check. |
