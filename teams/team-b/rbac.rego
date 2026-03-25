package backstage.rbac.team_b

import data.teams.team_b.roles as team_roles
import data.teams.team_b.group_roles as team_group_roles
import data.teams.team_b.user_roles as team_user_roles

default allow = false

# Helper: Get all roles assigned to the user (via groups or directly)
user_assigned_roles contains role if {
    some i, j
    group := input.claims.groups[i]
    role := team_group_roles[group][j]
}
user_assigned_roles contains role if {
    some j
    role = team_user_roles[input.userRef][j]
}

# Helper: Construct the specific entity reference string
# Example: "component:default/team-a-service"
requested_entity_ref := sprintf("%s:%s", [
    lower(input.entity.kind), 
    input.entity.metadata.namespace, 
    input.entity.metadata.name
])

# 1. Allow if the user has a role that grants the action on the specific Entity Reference
allow if {
    role := user_assigned_roles[_]
    role_perms := team_roles[role]
    requested_action := input.action
    
    # Check if the role grants the action on the exact entity string
    entity_actions := role_perms[requested_entity_ref]
    requested_action == entity_actions[_]
}

# 2. Allow if the user has a role that grants the action on the broad Entity Type (e.g., "API")
allow if {
    role := user_assigned_roles[_]
    role_perms := team_roles[role]
    requested_action := input.action
    requested_type := input.entityType
    
    # Check if the role grants the action broadly on the kind
    type_actions := role_perms[requested_type]
    requested_action == type_actions[_]
}

# 3. Specific Allow for Owners subgroup (can do everything)
allow if {
    group := input.claims.groups[_]
    endswith(group, "-owners")
}

# 4. Allow if user belongs to the group that owns the entity
allow if {
    user_groups := input.claims.groups
    entity_owner := input.entity.spec.owner
    entity_owner == user_groups[_]
}
