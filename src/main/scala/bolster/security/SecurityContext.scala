/*
 * Copyright 2023 Carlos Conyers
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package bolster.security

/**
 * Defines context in which permissions are granted.
 *
 * A `SecurityContext` establishes a pattern in which a restricted operation is
 * performed only if required permissions are granted; otherwise, a
 * [[SecurityViolation]] is raised.
 *
 * The following demonstrates how read/write access to an in-memory cache could
 * be implemented.
 *
 * {{{
 * import bolster.security.{ Permission, SecurityContext, UserContext }
 *
 * import scala.collection.concurrent.TrieMap
 *
 * object SecureCache:
 *   // Define permissions to read and write cache entries
 *   private val getPermission = Permission("cache:get")
 *   private val putPermission = Permission("cache:put")
 *
 *   private val cache = TrieMap[String, String](
 *     "gang starr"      -> "step in the arena",
 *     "digable planets" -> "blowout comb"
 *   )
 *
 *   def get(key: String)(using security: SecurityContext): String =
 *     // Test for read permission before getting cache entry
 *     security(getPermission) { cache(key) }
 *
 *   def put(key: String, value: String)(using security: SecurityContext): Unit =
 *     // Test for write permission before putting cache entry
 *     security(putPermission) { cache += key -> value }
 *
 * // Set security context to include read permission
 * given SecurityContext = UserContext(Permission("cache:get"))
 *
 * // Get cache entry
 * val classic = SecureCache.get("gang starr")
 *
 * // Throw SecurityViolation because write permission is not granted
 * SecureCache.put("sucker mc", classic)
 * }}}
 */
sealed trait SecurityContext:
  /**
   * Tests whether supplied permission is granted.
   *
   * @param perm permission
   *
   * @return `true` if permission is granted; otherwise, `false`
   */
  def test(perm: Permission): Boolean

  /**
   * Tests permission before applying operation.
   *
   * If supplied permission is granted, the operation is applied; otherwise,
   * [[SecurityViolation]] is thrown.
   *
   * @param perm permission
   * @param op operation
   *
   * @return operation value
   *
   * @throws SecurityViolation if permission is not granted
   */
  def apply[T](perm: Permission)(op: => T): T

  /**
   * Tests permissions before applying operation.
   *
   * If any of supplied permissions is granted, the operation is applied;
   * otherwise, [[SecurityViolation]] is thrown.
   *
   * @param perms permissions
   * @param op operation
   *
   * @return operation value
   *
   * @throws SecurityViolation if no permission is granted
   *
   * @note The operation is authorized if `perms` is empty.
   */
  def any[T](perms: Set[Permission])(op: => T): T

  /**
   * Tests permissions before applying operation.
   *
   * If any of supplied permissions is granted, the operation is applied;
   * otherwise, [[SecurityViolation]] is thrown.
   *
   * @param one permission
   * @param more additional permissions
   * @param op operation
   *
   * @return operation value
   *
   * @throws SecurityViolation if no permission is granted
   */
  def any[T](one: Permission, more: Permission*)(op: => T): T

  /**
   * Tests permissions before applying operation.
   *
   * If all supplied permissions are granted, the operation is applied;
   * otherwise, [[SecurityViolation]] is thrown.
   *
   * @param perms permissions
   * @param op operation
   *
   * @return operation value
   *
   * @throws SecurityViolation if all permissions are not granted
   *
   * @note The operation is authorized if `perms` is empty.
   */
  def all[T](perms: Set[Permission])(op: => T): T

  /**
   * Tests permissions before applying operation.
   *
   * If all supplied permissions are granted, the operation is applied;
   * otherwise, [[SecurityViolation]] is thrown.
   *
   * @param one permission
   * @param more additional permissions
   * @param op operation
   *
   * @return operation value
   *
   * @throws SecurityViolation if all permissions are not granted
   */
  def all[T](one: Permission, more: Permission*)(op: => T): T

/**
 * Defines root context in which all permissions are granted.
 *
 * @see [[UserContext]]
 */
object RootContext extends SecurityContext:
  /** @inheritdoc */
  def test(perm: Permission): Boolean = true

  /** @inheritdoc */
  def apply[T](perm: Permission)(op: => T): T = op

  /** @inheritdoc */
  def any[T](perms: Set[Permission])(op: => T): T = op

  /** @inheritdoc */
  def any[T](one: Permission, more: Permission*)(op: => T): T = op

  /** @inheritdoc */
  def all[T](perms: Set[Permission])(op: => T): T = op

  /** @inheritdoc */
  def all[T](one: Permission, more: Permission*)(op: => T): T = op

  /** Gets string representation. */
  override val toString = "RootContext"

/**
 * Defines user context in which a set of permissions is granted.
 *
 * @see [[RootContext]]
 */
sealed trait UserContext extends SecurityContext:
  /** Gets permissions. */
  def permissions: Set[Permission]

  /**
   * Creates new security context by adding supplied permissions to existing set
   * of permissions.
   *
   * @param perms permissions
   *
   * @return new security context
   */
  def grant(perms: Set[Permission]): UserContext

  /**
   * Creates new security context by adding supplied permissions to existing set
   * of permissions.
   *
   * @param one  permission
   * @param more additional permissions
   *
   * @return new security context
   */
  def grant(one: Permission, more: Permission*): UserContext

  /**
   * Creates new security context by removing supplied permissions from existing
   * set of permissions.
   *
   * @param perms permissions
   *
   * @return new security context
   */
  def revoke(perms: Set[Permission]): UserContext

  /**
   * Creates new security context by removing supplied permissions from existing
   * set of permissions.
   *
   * @param one  permission
   * @param more additional permissions
   *
   * @return new security context
   */
  def revoke(one: Permission, more: Permission*): UserContext

/** Provides user context factory. */
object UserContext:
  /**
   * Creates user context with supplied permissions.
   *
   * @param perms permissions
   */
  def apply(perms: Set[Permission]): UserContext =
    UserContextImpl(perms)

  /**
   * Creates user context with supplied permissions.
   *
   * @param one permission
   * @param more additional permissions
   */
  def apply(perms: Seq[Permission]): UserContext =
    apply(perms.toSet)

  /**
   * Creates user context with supplied permissions.
   *
   * @param one permission
   * @param more additional permissions
   */
  def apply(one: Permission, more: Permission*): UserContext =
    apply((one +: more).toSet)

  /**
   * Destructures user context to its permissions.
   *
   * @param security user context
   */
  def unapply(security: UserContext): Option[Set[Permission]] =
    Some(security.permissions)

private case class UserContextImpl(permissions: Set[Permission]) extends UserContext:
  def test(perm: Permission): Boolean =
    permissions.contains(perm)

  def apply[T](perm: Permission)(op: => T): T =
    test(perm) match
      case true  => op
      case false => throw SecurityViolation(s"Permission not granted: ${perm.name}")

  def any[T](perms: Set[Permission])(op: => T): T =
    (perms.isEmpty || perms.exists(test)) match
      case true  => op
      case false => throw SecurityViolation(s"None of permissions granted: ${perms.map(_.name).mkString(", ")}")

  def any[T](one: Permission, more: Permission*)(op: => T): T =
    any((one +: more).toSet)(op)

  def all[T](perms: Set[Permission])(op: => T): T =
    perms.find(!test(_)) match
      case Some(perm) => throw SecurityViolation(s"Permission not granted: ${perm.name}")
      case None       => op

  def all[T](one: Permission, more: Permission*)(op: => T): T =
    all((one +: more).toSet)(op)

  def grant(perms: Set[Permission]): UserContext =
    copy(permissions = permissions ++ perms)

  def grant(one: Permission, more: Permission*): UserContext =
    grant((one +: more).toSet)

  def revoke(perms: Set[Permission]): UserContext =
    copy(permissions = permissions &~ perms)

  def revoke(one: Permission, more: Permission*): UserContext =
    revoke((one +: more).toSet)

  override lazy val toString = s"UserContext($permissions)"
