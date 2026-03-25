package backstage.rbac

import data.backstage.roles
import data.backstage.group_roles

# --- MOCK DATA ---
mock_roles = {
    "developer": {
        "API": ["create", "read", "edit", "delete"],
        "App": ["create", "read", "edit", "delete", "deploy"],
        "Data": ["create", "read", "edit", "delete"]
    },
    "basic": {
        "API": ["read"],
        "App": ["read"],
        "Data": ["read"]
    }
}

mock_group_roles = {
    "group:default/team-a": ["developer"],
    "group:default/team-b": ["developer"],
    "group:default/guest-team": ["basic"]
}
# -----------------

test_basic_user_can_read_api {
    allow with input as {
        "userRef": "user:default/charlie",
        "claims": { "groups": ["group:default/team-a"] },
        "action": "read",
        "entityType": "API"
    } with data.backstage.roles as mock_roles with data.backstage.group_roles as mock_group_roles
}

test_basic_user_cannot_delete_api {
    not allow with input as {
        "userRef": "user:default/charlie",
        "claims": { "groups": ["group:default/team-a"] },
        "action": "delete",
        "entityType": "API"
    } with data.backstage.roles as mock_roles with data.backstage.group_roles as mock_group_roles
}

test_developer_can_deploy_app {
    allow with input as {
        "userRef": "user:default/bob",
        "claims": { "groups": ["group:default/team-a-developers", "group:default/team-a"] },
        "action": "deploy",
        "entityType": "App"
    } with data.backstage.roles as mock_roles with data.backstage.group_roles as mock_group_roles
}

test_owner_can_do_anything {
    allow with input as {
        "userRef": "user:default/alice",
        "claims": { "groups": ["group:default/team-a-owners", "group:default/team-a"] },
        "action": "destroy_universe",
        "entityType": "App"
    } with data.backstage.roles as mock_roles with data.backstage.group_roles as mock_group_roles
}
