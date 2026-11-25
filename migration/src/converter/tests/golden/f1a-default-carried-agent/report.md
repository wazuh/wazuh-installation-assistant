# Migration report

Status: candidate_requires_lab_validation.

Candidate files are incomplete while decisions remain. No runtime validation was run.

All input values are masked, including unknown values. Generated configs retain required secrets; protect them.

| Option id | Classification | Guide section | Action left to user |
|---|---|---|---|
| f1a-default-carried-agent.conf:/agent_config[1]/client_buffer[1]/disabled[1] | dropped_with_replacement | manager-4x-to-5x.md#groups | Remove ignored block; replacement: agent/batch; choose batching settings separately. |
| f1a-default-carried-agent.conf:/agent_config[1]/client_buffer[1]/queue_size[1] | dropped_with_replacement | manager-4x-to-5x.md#groups | Remove ignored block; replacement: agent/batch; choose batching settings separately. |
| f1a-default-carried-agent.conf:/agent_config[1]/client_buffer[1]/events_per_second[1] | dropped_with_replacement | manager-4x-to-5x.md#groups | Remove ignored block; replacement: agent/batch; choose batching settings separately. |
