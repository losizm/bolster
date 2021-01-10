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
package little.security

class SecurityContextSpec extends org.scalatest.flatspec.AnyFlatSpec {
  val create = Permission("create")
  val select = Permission("select")
  val insert = Permission("insert")
  val update = Permission("update")
  val delete = Permission("delete")
  val guest  = UserPermission("guest")
  val root   = UserPermission("root")
  val staff  = GroupPermission("staff")
  val wheel  = GroupPermission("wheel")

  val security = UserContext("guest", "staff", select, update)
  val empty = Set.empty[Permission]

  it should "create user context" in {
    val s1 = UserContext("guest", "staff", select, update)
    assert(s1.userId == "guest")
    assert(s1.groupId == "staff")
    assert(s1.test(guest))
    assert(s1.test(staff))
    assert(s1.test(select))
    assert(s1.test(update))

    val s2 = UserContext("guest", "staff", select, update, staff, wheel)
    assert(s2.userId == "guest")
    assert(s2.groupId == "staff")
    assert(s2.test(guest))
    assert(s2.test(staff))
    assert(s2.test(wheel))
    assert(s2.test(select))
    assert(s2.test(update))

    val s3 = UserContext("guest", "staff", select, update, guest, staff, wheel)
    assert(s3.userId == "guest")
    assert(s3.groupId == "staff")
    assert(s3.test(guest))
    assert(s3.test(staff))
    assert(s3.test(wheel))
    assert(s3.test(select))
    assert(s3.test(update))

    assertThrows[IllegalArgumentException] {
      UserContext("guest", "staff", select, update, guest, root)
    }
  }

  it should "grant permissions" in {
    val s1 = UserContext("guest", "staff", select, update)
    assert(s1.userId == "guest")
    assert(s1.groupId == "staff")
    assert(s1.test(guest))
    assert(s1.test(staff))
    assert(s1.test(select))
    assert(s1.test(update))

    val s2 = s1.grant(insert)
    assert(s2.userId == "guest")
    assert(s2.groupId == "staff")
    assert(s2.test(guest))
    assert(s2.test(staff))
    assert(s2.test(select))
    assert(s2.test(update))
    assert(s2.test(insert))

    val s3 = s1.grant(insert, delete)
    assert(s3.userId == "guest")
    assert(s3.groupId == "staff")
    assert(s3.test(guest))
    assert(s3.test(staff))
    assert(s3.test(select))
    assert(s3.test(update))
    assert(s3.test(insert))
    assert(s3.test(delete))

    val s4 = s1.grant(empty)
    assert(s4.userId == "guest")
    assert(s4.groupId == "staff")
    assert(s4.test(guest))
    assert(s4.test(staff))
    assert(s4.test(select))
    assert(s4.test(update))

    val s5 = s1.grant(s1.permissions)
    assert(s5.userId == "guest")
    assert(s5.groupId == "staff")
    assert(s5.test(guest))
    assert(s5.test(staff))
    assert(s5.test(select))
    assert(s5.test(update))
  }

  it should "revoke permissions" in {
    val s1 = UserContext("guest", "staff", select, update)
    assert(s1.userId == "guest")
    assert(s1.groupId == "staff")
    assert(s1.test(guest))
    assert(s1.test(staff))
    assert(s1.test(select))
    assert(s1.test(update))

    val s2 = s1.revoke(update)
    assert(s2.userId == "guest")
    assert(s2.groupId == "staff")
    assert(s2.test(guest))
    assert(s2.test(staff))
    assert(s2.test(select))
    assert(!s2.test(update))

    val s3 = s1.revoke(select, update)
    assert(s3.userId == "guest")
    assert(s3.groupId == "staff")
    assert(s3.test(guest))
    assert(s3.test(staff))
    assert(!s3.test(select))
    assert(!s3.test(update))

    val s4 = s1.revoke(empty)
    assert(s4.userId == "guest")
    assert(s4.groupId == "staff")
    assert(s4.test(guest))
    assert(s4.test(staff))
    assert(s4.test(select))
    assert(s4.test(update))

    val s5 = s1.revoke(s1.permissions)
    assert(s5.userId == "guest")
    assert(s5.groupId == "staff")
    assert(s5.test(guest))
    assert(s5.test(staff))
    assert(!s5.test(select))
    assert(!s5.test(update))
  }

  it should "authorize operation" in {
    assert { security(select)(1) == 1 }
    assert { security(update)(1) == 1 }

    assert { security(guest)(1) == 1 }
    assert { security(staff)(1) == 1 }
  }

  it should "not authorize operation" in {
    assertThrows[SecurityViolation] { security(insert)(1) }
    assertThrows[SecurityViolation] { security(delete)(1) }

    assertThrows[SecurityViolation] { security(root)(1) }
    assertThrows[SecurityViolation] { security(wheel)(1) }
  }

  it should "authorize operation for any permission" in {
    assert { security.any(select, create, insert)(1) == 1 }
    assert { security.any(insert, select, create)(1) == 1 }
    assert { security.any(create, insert, select)(1) == 1 }

    assert { security.any(select, create, update)(1) == 1 }
    assert { security.any(update, select, create)(1) == 1 }
    assert { security.any(create, update, select)(1) == 1 }

    assert { security.any(select, update)(1) == 1 }
    assert { security.any(update, select)(1) == 1 }

    assert { security.any(select)(1) == 1 }
    assert { security.any(update)(1) == 1 }

    assert { security.any(empty)(1) == 1 }
  }

  it should "not authorize operation for any permission" in {
    assertThrows[SecurityViolation] { security.any(insert, create, delete)(1) }
    assertThrows[SecurityViolation] { security.any(insert, create)(1) }
    assertThrows[SecurityViolation] { security.any(insert)(1) }
    assertThrows[SecurityViolation] { security.any(root, wheel)(1) }
  }

  it should "authorize operation for all permission" in {
    assert { security.all(select, update)(1) == 1 }
    assert { security.all(update, select)(1) == 1 }

    assert { security.all(update, select, update)(1) == 1 }

    assert { security.all(select)(1) == 1 }
    assert { security.all(update)(1) == 1 }

    assert { security.all(empty)(1) == 1 }
  }

  it should "not authorize operation for all permission" in {
    assertThrows[SecurityViolation] { security.all(select, create, insert)(1) }
    assertThrows[SecurityViolation] { security.all(insert, select, create)(1) }
    assertThrows[SecurityViolation] { security.all(create, insert, select)(1) }

    assertThrows[SecurityViolation] { security.all(select, create, update)(1) }
    assertThrows[SecurityViolation] { security.all(update, select, create)(1) }
    assertThrows[SecurityViolation] { security.all(create, update, select)(1) }

    assertThrows[SecurityViolation] { security.all(insert, update)(1) }
    assertThrows[SecurityViolation] { security.all(update, insert)(1) }
    assertThrows[SecurityViolation] { security.all(insert, select)(1) }
    assertThrows[SecurityViolation] { security.all(select, insert)(1) }

    assertThrows[SecurityViolation] { security.all(create)(1) }
    assertThrows[SecurityViolation] { security.all(insert)(1) }
  }
}
