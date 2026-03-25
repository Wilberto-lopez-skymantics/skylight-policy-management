package backstage.rbac

import data.backstage.rbac.team_a
import data.backstage.rbac.team_b

default allow = false

allow {
    team_a.allow
}

allow {
    team_b.allow
}
