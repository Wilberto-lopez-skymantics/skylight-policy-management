package backstage.rbac.team_a

team_group_roles := data.teams["team-a"].group_roles
team_user_roles  := data.teams["team-a"].user_roles
team_roles       := data.teams["team-a"].roles

default allow = false

# Allow if user's group (by name, ignoring namespace) has a role that allows the action on the entity type
allow {
    group := input.claims.groups[_]
    group_name := split(group, "/")[1]

    team_group_roles[key]
    split(key, "/")[1] == group_name

    role := team_group_roles[key][_]
    actions := team_roles[role][input.entityType]
    input.action == actions[_]
}

# Allow if user's group has a role that allows the action on the specific entity ref
allow {
    group := input.claims.groups[_]
    group_name := split(group, "/")[1]

    team_group_roles[key]
    split(key, "/")[1] == group_name

    role := team_group_roles[key][_]
    ref := sprintf("%s:%s/%s", [
        lower(input.entity.kind),
        input.entity.metadata.namespace,
        input.entity.metadata.name
    ])
    actions := team_roles[role][ref]
    input.action == actions[_]
}

# Allow if user directly has a role that allows the action on the entity type
allow {
    user_name := split(input.userRef, "/")[1]

    team_user_roles[key]
    split(key, "/")[1] == user_name

    role := team_user_roles[key][_]
    actions := team_roles[role][input.entityType]
    input.action == actions[_]
}

# Allow if user belongs to the owning group (namespace-agnostic)
allow {
    group := input.claims.groups[_]
    owner := input.entity.spec.owner
    split(group, "/")[1] == split(owner, "/")[1]
}
