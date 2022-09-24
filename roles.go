package auth2

const ROLE_SERVICE = "service"
const ROLE_SUPERADMIN = "superadmin"
const ROLE_ADMIN = "admin"
const ROLE_USER = "user"
const ROLE_ANONYMOUS = "anonymous"

var RolesAdmin = []string{ROLE_ADMIN, ROLE_SUPERADMIN}
var RolesUsersAndAdmin = []string{ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN}
var RolesServiceAndUsersAndAdmin = []string{ROLE_SERVICE, ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN}
var RolesServiceAndAdmin = []string{ROLE_SERVICE, ROLE_ADMIN, ROLE_SUPERADMIN}
var RolesServiceAndSuperadmin = []string{ROLE_SERVICE, ROLE_SUPERADMIN}
var RolesAllAndAnon = []string{ROLE_SERVICE, ROLE_SUPERADMIN, ROLE_ADMIN, ROLE_USER, ROLE_ANONYMOUS}

func HasRole(user *User, role string) bool {
	for _, ur := range user.Roles {
		if ur == role {
			return true
		}
	}

	return false
}

func IntersectsRoles(user *User, roles ...string) bool {
	for _, ur := range user.Roles {
		for _, mr := range roles {
			if ur == mr {
				return true
			}
		}
	}

	return false
}
