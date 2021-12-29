/*
 * Copyright 2021 Carlos Conyers
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

class PermissionSpec extends org.scalatest.flatspec.AnyFlatSpec:
  it should "create permission" in {
    assert(Permission("read").name == "read")
  }

  it should "destructure permission" in {
    assert(
      Permission("write") match
        case Permission(name) => name == "write"
        case _                => false
    )

    assert(
      Permission("write") match
        case Permission("write") => true
        case _                   => false
    )

    assert(
      UserPermission("guest") match
        case UserPermission(userId) => userId == "guest"
        case _                      => false
    )

    assert(
      UserPermission("guest") match
        case UserPermission("guest") => true
        case _                       => false
    )

    assert(
      GroupPermission("staff") match
        case GroupPermission(groupId) => groupId == "staff"
        case _                        => false
    )

    assert(
      GroupPermission("staff") match
        case GroupPermission("staff") => true
        case _                        => false
    )
  }

  it should "create set of permissions" in {
    var perms = Permission.toSet("read", "write", "execute")
    assert(perms.size == 3)
    assert(perms.contains(Permission("read")))
    assert(perms.contains(Permission("write")))
    assert(perms.contains(Permission("execute")))

    perms = Permission.toSet("read", "write", "read", "execute", "write")
    assert(perms.size == 3)
    assert(perms.contains(Permission("read")))
    assert(perms.contains(Permission("write")))
    assert(perms.contains(Permission("execute")))

    assert(Permission.toSet(Nil).isEmpty)
  }

  it should "not create permissions with no name" in {
    assertThrows[NullPointerException](Permission(null))
    assertThrows[NullPointerException](Permission.toSet("read", "write", null))

    assertThrows[IllegalArgumentException](Permission(""))
    assertThrows[IllegalArgumentException](Permission.toSet("read", "write", ""))
  }

  it should "create set of user permissions" in {
    var perms = UserPermission.toSet("ishmael", "isaac", "guest")
    assert(perms.size == 3)
    assert(perms.contains(UserPermission("ishmael")))
    assert(perms.contains(UserPermission("isaac")))
    assert(perms.contains(UserPermission("guest")))

    perms = UserPermission.toSet("ishmael", "isaac", "ishmael", "guest", "isaac")
    assert(perms.size == 3)
    assert(perms.contains(UserPermission("ishmael")))
    assert(perms.contains(UserPermission("isaac")))
    assert(perms.contains(UserPermission("guest")))

    assert(UserPermission.toSet(Nil).isEmpty)
  }

  it should "not create user permissions with null identifer" in {
    assertThrows[NullPointerException](UserPermission(null))
    assertThrows[NullPointerException](UserPermission.toSet("ishmael", "isaac", null))
  }

  it should "create set of group permissions" in {
    var perms = GroupPermission.toSet("staff", "admin", "developers")
    assert(perms.size == 3)
    assert(perms.contains(GroupPermission("staff")))
    assert(perms.contains(GroupPermission("admin")))
    assert(perms.contains(GroupPermission("developers")))

    perms = GroupPermission.toSet("staff", "admin", "staff", "developers", "admin")
    assert(perms.size == 3)
    assert(perms.contains(GroupPermission("staff")))
    assert(perms.contains(GroupPermission("admin")))
    assert(perms.contains(GroupPermission("developers")))

    assert(GroupPermission.toSet(Nil).isEmpty)
  }

  it should "not create group permissions with null identifer" in {
    assertThrows[NullPointerException](GroupPermission(null))
    assertThrows[NullPointerException](GroupPermission.toSet("staff", "admin", null))
  }
