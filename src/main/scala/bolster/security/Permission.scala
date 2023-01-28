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

/** Defines permission by name. */
sealed trait Permission:
  /** Gets name. */
  def name: String

/** Provides permission factory. */
object Permission:
  /**
   * Creates permission with supplied name.
   *
   * @param name permission name
   *
   * @throws IllegalArgumentException if name is blank
   */
  def apply(name: String): Permission =
    name.trim() match
      case ""    => throw IllegalArgumentException()
      case value => PermissionImpl(value)

  /**
   * Creates set of permissions with supplied names.
   *
   * @param names permission names
   */
  def toSet(names: Iterable[String]): Set[Permission] =
    names.toSet.map(apply)

  /**
   * Creates set of permissions with supplied names.
   *
   * @param one permission name
   * @param more additional permission names
   */
  def toSet(one: String, more: String*): Set[Permission] =
    toSet(one +: more)

  /**
   * Destructures permission to its name
   *
   * @param perm permission
   */
  def unapply(perm: Permission): Option[String] =
    Some(perm.name)

private case class PermissionImpl(name: String) extends Permission:
  override lazy val toString = s"Permission($name)"
