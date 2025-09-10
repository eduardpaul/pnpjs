import { SecurableQueryable, IBasePermissions, PermissionKind } from "./types.js";
import { SPInstance, SPQueryable, spPost } from "../spqueryable.js";

/**
* Gets the effective permissions for the user supplied
*
* @param loginName The claims username for the user (ex: i:0#.f|membership|user@domain.com)
*/
export async function getUserEffectivePermissions(this: SecurableQueryable, loginName: string): Promise<IBasePermissions> {

    const q = SPInstance(this, "getUserEffectivePermissions(@user)");
    q.query.set("@user", `'${loginName}'`);
    return q();
}

/**
 * Gets the effective permissions for the current user
 */
export async function getCurrentUserEffectivePermissions(this: SecurableQueryable): Promise<IBasePermissions> {

    return SPQueryable(this, "EffectiveBasePermissions")();
}

/**
 * Breaks the security inheritance at this level optinally copying permissions and clearing subscopes
 *
 * @param copyRoleAssignments If true the permissions are copied from the current parent scope
 * @param clearSubscopes Optional. true to make all child securable objects inherit role assignments from the current object
 */
export async function breakRoleInheritance(this: SecurableQueryable, copyRoleAssignments = false, clearSubscopes = false): Promise<void> {
    return spPost(SPQueryable(this, `breakroleinheritance(copyroleassignments=${copyRoleAssignments}, clearsubscopes=${clearSubscopes})`));
}

/**
 * Removes the local role assignments so that it re-inherit role assignments from the parent object.
 *
 */
export async function resetRoleInheritance(this: SecurableQueryable): Promise<void> {
    return spPost(SPQueryable(this, "resetroleinheritance"));
}

/**
 * Determines if a given user has the appropriate permissions
 *
 * @param loginName The user to check
 * @param permission The permission being checked
 */
export async function userHasPermissions(this: SecurableQueryable, loginName: string, permission: PermissionKind): Promise<boolean> {

    const perms = await getUserEffectivePermissions.call(this, loginName);
    return this.hasPermissions(perms, permission);
}

/**
 * Determines if the current user has the requested permissions
 *
 * @param permission The permission we wish to check
 */
export async function currentUserHasPermissions(this: SecurableQueryable, permission: PermissionKind): Promise<boolean> {

    const perms = await getCurrentUserEffectivePermissions.call(this);
    return this.hasPermissions(perms, permission);
}

/**
 * Taken from sp.js, checks the supplied permissions against the mask
 *
 * @param value The security principal's permissions on the given object
 * @param perm The permission checked against the value
 */
/* eslint-disable no-bitwise */
export function hasPermissions(value: IBasePermissions, perm: PermissionKind): boolean {

    if (!perm) {
        return true;
    }
    if (perm === PermissionKind.FullMask) {
        return (value.High & 32767) === 32767 && value.Low === 65535;
    }

    perm = perm - 1;
    let num = 1;

    if (perm >= 0 && perm < 32) {
        num = num << perm;
        return 0 !== (value.Low & num);
    } else if (perm >= 32 && perm < 64) {
        num = num << perm - 32;
        return 0 !== (value.High & num);
    }
    return false;
}

const FULL_MASK = 0xffffffff >>> 0;

const bitIndex = (perm: PermissionKind): number | null => {
    if (perm === PermissionKind.EmptyMask || perm === PermissionKind.FullMask) return null;
    const idx = Number(perm) - 1; // PermissionKind is 1-based
    return idx >= 0 && idx < 64 ? idx : null;
};

// Aux method to apply a bitmask operation to Low or High segment of IBasePermissions
const applyMask = (
    value: IBasePermissions,
    idx: number,
    op: (seg: number, mask: number) => number
): IBasePermissions => {
    if (idx < 32) {
        const mask = (1 << idx) >>> 0;
        return { ...value, Low: op(value.Low >>> 0, mask) >>> 0 };
    } else {
        const mask = (1 << (idx - 32)) >>> 0;
        return { ...value, High: op(value.High >>> 0, mask) >>> 0 };
    }
};

/**
 * Adds a specified permission to the given base permissions object.
 *
 * @param value - The current base permissions object.
 * @param perm - The permission kind to add.
 * @returns The updated base permissions object with the specified permission added.
 *
 * - If `perm` is `PermissionKind.EmptyMask`, the original permissions are returned (no change).
 * - If `perm` is `PermissionKind.FullMask`, all permission bits are granted.
 * - Otherwise, the specific permission bit corresponding to `perm` is set.
 */
export function addPermission(value: IBasePermissions, perm: PermissionKind): IBasePermissions {
    if (perm === PermissionKind.EmptyMask) return value; // no-op
    if (perm === PermissionKind.FullMask) {
        // grant all *defined* bits
        return { ...value, Low: FULL_MASK, High: FULL_MASK };
    }
    const idx = bitIndex(perm);
    if (idx === null) return value;
    return applyMask(value, idx, (seg, mask) => (seg | mask) >>> 0);
}

/**
 * Removes a specific permission from the given permissions value.
 *
 * @param value - The current permissions represented as an `IBasePermissions` object.
 * @param perm - The permission to remove, specified as a `PermissionKind` enum value.
 * @returns The updated `IBasePermissions` object with the specified permission removed.
 *
 * - If `perm` is `PermissionKind.EmptyMask`, the original permissions are returned unchanged.
 * - If `perm` is `PermissionKind.FullMask`, all permissions are cleared.
 * - If the bit index for the permission is not found, the original permissions are returned unchanged.
 * - Otherwise, the specified permission bit is cleared.
 */
export function removePermission(value: IBasePermissions, perm: PermissionKind): IBasePermissions {
    if (perm === PermissionKind.EmptyMask) return value; // no-op
    if (perm === PermissionKind.FullMask) {
        // clear all bits
        return { ...value, Low: 0, High: 0 };
    }
    const idx = bitIndex(perm);
    if (idx === null) return value;
    return applyMask(value, idx, (seg, mask) => (seg & ~mask) >>> 0);
}
/* eslint-enable no-bitwise */
