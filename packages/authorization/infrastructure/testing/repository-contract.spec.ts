import { InMemoryPermissionRepository } from "../fakes/in-memory-permission-repository.js";
import { InMemoryRoleRepository } from "../fakes/in-memory-role-repository.js";
import { InMemoryUserRoleAssignmentRepository } from "../fakes/in-memory-user-role-assignment-repository.js";

import { permissionRepositoryContract } from "./contracts/permission-repository.contract.js";
import { roleRepositoryContract } from "./contracts/role-repository.contract.js";
import { userRoleAssignmentRepositoryContract } from "./contracts/user-role-assignment-repository.contract.js";

roleRepositoryContract(() => new InMemoryRoleRepository());
permissionRepositoryContract(() => new InMemoryPermissionRepository());
userRoleAssignmentRepositoryContract(() => new InMemoryUserRoleAssignmentRepository());
