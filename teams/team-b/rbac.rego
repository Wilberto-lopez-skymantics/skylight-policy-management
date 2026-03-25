package backstage.rbac.team_b

team_roles := data.teams["team-b"].roles
team_group_roles := data.teams["team-b"].group_roles
team_user_roles := data.teams["team-b"].user_roles

default allow = false

# Helper: Get all roles assigned to the user (via groups or directly)
user_assigned_roles[role] {
    some i, j, k
    group := input.claims.groups[i]
    group_name := split(group, "/")[1]
    
    stored_group := [key | _ = team_group_roles[key]][j]
    stored_group_name := split(stored_group, "/")[1]
    
    group_name == stored_group_name
    role = team_group_roles[stored_group][k]
}
user_assigned_roles[role] {
    some j, k
    user_name := split(input.userRef, "/")[1]
    
    stored_user := [key | _ = team_user_roles[key]][j]
    stored_user_name := split(stored_user, "/")[1]
    
    user_name == stored_user_name
    role = team_user_roles[stored_user][k]
}

# Helper: Construct the specific entity reference string
# Example: "component:default/team-a-service"
requested_entity_ref := sprintf("%s:%s", [
    lower(input.entity.kind), 
    input.entity.metadata.namespace, 
    input.entity.metadata.name
])

# 1. Allow if the user has a role that grants the action on the specific Entity Reference
allow {
    role := user_assigned_roles[_]
    role_perms := team_roles[role]
    requested_action := input.action
    
    # Check if the role grants the action on the exact entity string
    entity_actions := role_perms[requested_entity_ref]
    requested_action == entity_actions[_]
}

# 2. Allow if the user has a role that grants the action on the broad Entity Type (e.g., "API")
allow {
    role := user_assigned_roles[_]
    role_perms := team_roles[role]
    requested_action := input.action
    requested_type := input.entityType
    
    # Check if the role grants the action broadly on the kind
    type_actions := role_perms[requested_type]
    requested_action == type_actions[_]
}

# 3. Specific Allow for Owners subgroup (can do everything)
allow {
    group := input.claims.groups[_]
    endswith(group, "-owners")
}

# 4. Allow if user belongs to the group that owns the entity
allow {
    user_group := input.claims.groups[_]
    entity_owner := input.entity.spec.owner
    split(user_group, "/")[1] == split(entity_owner, "/")[1]
}
