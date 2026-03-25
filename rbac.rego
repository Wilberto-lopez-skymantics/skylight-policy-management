package backstage.rbac

import data.backstage.rbac.team_a
import data.backstage.rbac.team_b

import rego.v1

default allow := false

allow if {
    team_a.allow
}

allow if {
    team_b.allow
}
