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

class SecurityContextSpec extends org.scalatest.flatspec.AnyFlatSpec:
  val create = Permission("action:create")
  val select = Permission("action:select")
  val insert = Permission("action:insert")
  val update = Permission("action:update")
  val delete = Permission("action:delete")
  val lupita = Permission("user:lupita")
  val root   = Permission("user:root")
  val staff  = Permission("group:staff")
  val wheel  = Permission("group:wheel")

  val security = UserContext(lupita, staff, select, update)
  val empty = Set.empty[Permission]

  it should "get empty user context" in {
    val s1 = UserContext.empty
    val s2 = UserContext(empty)

    assert { s1 == UserContext.empty }
    assert { s2 == UserContext.empty }

    assert { s1.permissions.isEmpty }
    assert { !s1.test(insert) }
    assert { !s1.test(update) }
    assert { !s1.test(delete) }

    assert { s1.testAny(empty) }
    assert { !s1.testAny(insert) }
    assert { !s1.testAny(insert, update, delete) }

    assert { s1.testAll(empty) }
    assert { !s1.testAll(insert) }
    assert { !s1.testAll(insert, update, delete) }

    assertThrows[SecurityViolation] { s1(insert)(1) }

    assert { s1.any(empty)(1) == 1 }
    assertThrows[SecurityViolation] { s1.any(insert)(1) }
    assertThrows[SecurityViolation] { s1.any(insert, update, delete)(1) }

    assert { s1.all(empty)(1) == 1 }
    assertThrows[SecurityViolation] { s1.all(insert)(1) }
    assertThrows[SecurityViolation] { s1.all(insert, update, delete)(1) }
  }

  it should "create user context" in {
    val s1 = UserContext(lupita, staff, select, update)
    assert(s1.test(lupita))
    assert(s1.test(staff))
    assert(s1.test(select))
    assert(s1.test(update))

    val s2 = UserContext(lupita, staff, select, update, wheel)
    assert(s2.test(lupita))
    assert(s2.test(staff))
    assert(s2.test(wheel))
    assert(s2.test(select))
    assert(s2.test(update))

    val s3 = UserContext(lupita, staff, select, update, wheel)
    assert(s3.test(lupita))
    assert(s3.test(staff))
    assert(s3.test(wheel))
    assert(s3.test(select))
    assert(s3.test(update))
  }

  "UserContext" should "grant permissions" in {
    val s1 = UserContext(lupita, staff, select, update)
    assert(s1.test(lupita))
    assert(s1.test(staff))
    assert(s1.test(select))
    assert(s1.test(update))

    val s2 = s1.grant(insert)
    assert(s2.test(lupita))
    assert(s2.test(staff))
    assert(s2.test(select))
    assert(s2.test(update))
    assert(s2.test(insert))

    val s3 = s1.grant(insert, delete)
    assert(s3.test(lupita))
    assert(s3.test(staff))
    assert(s3.test(select))
    assert(s3.test(update))
    assert(s3.test(insert))
    assert(s3.test(delete))

    val s4 = s1.grant(empty)
    assert(s4.test(lupita))
    assert(s4.test(staff))
    assert(s4.test(select))
    assert(s4.test(update))

    val s5 = s1.grant(s1.permissions)
    assert(s5.test(lupita))
    assert(s5.test(staff))
    assert(s5.test(select))
    assert(s5.test(update))
  }

  it should "revoke permissions" in {
    val s1 = UserContext(lupita, staff, select, update)
    assert(s1.test(lupita))
    assert(s1.test(staff))
    assert(s1.test(select))
    assert(s1.test(update))

    val s2 = s1.revoke(update)
    assert(s2.test(lupita))
    assert(s2.test(staff))
    assert(s2.test(select))
    assert(!s2.test(update))

    val s3 = s1.revoke(select, update)
    assert(s3.test(lupita))
    assert(s3.test(staff))
    assert(!s3.test(select))
    assert(!s3.test(update))

    val s4 = s1.revoke(empty)
    assert(s4.test(lupita))
    assert(s4.test(staff))
    assert(s4.test(select))
    assert(s4.test(update))

    val s5 = s1.revoke(s1.permissions)
    assert(!s5.test(lupita))
    assert(!s5.test(staff))
    assert(!s5.test(select))
    assert(!s5.test(update))
  }

  it should "authorize operation" in {
    assert { security(select)(1) == 1 }
    assert { security(update)(1) == 1 }

    assert { security(lupita)(1) == 1 }
    assert { security(staff)(1) == 1 }
  }

  it should "not authorize operation" in {
    assertThrows[SecurityViolation] { security(insert)(1) }
    assertThrows[SecurityViolation] { security(delete)(1) }

    assertThrows[SecurityViolation] { security(root)(1) }
    assertThrows[SecurityViolation] { security(wheel)(1) }
  }

  it should "test for any permission" in {
    assert { security.testAny(select, create, insert) }
    assert { security.testAny(insert, select, create) }
    assert { security.testAny(create, insert, select) }

    assert { security.testAny(select, create, update) }
    assert { security.testAny(update, select, create) }
    assert { security.testAny(create, update, select) }

    assert { security.testAny(select, update) }
    assert { security.testAny(update, select) }

    assert { security.testAny(select) }
    assert { security.testAny(update) }

    assert { security.testAny(empty) }

    assert { !security.testAny(insert, create, delete) }
    assert { !security.testAny(insert, create) }
    assert { !security.testAny(insert) }
    assert { !security.testAny(root, wheel) }
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

  it should "test for all permissions" in {
    assert { security.testAll(select, update) }
    assert { security.testAll(update, select) }

    assert { security.testAll(update, select, update) }

    assert { security.testAll(select) }
    assert { security.testAll(update) }

    assert { security.testAll(empty) }

    assert { !security.testAll(select, create, insert) }
    assert { !security.testAll(insert, select, create) }
    assert { !security.testAll(create, insert, select) }

    assert { !security.testAll(select, create, update) }
    assert { !security.testAll(update, select, create) }
    assert { !security.testAll(create, update, select) }

    assert { !security.testAll(insert, update) }
    assert { !security.testAll(update, insert) }
    assert { !security.testAll(insert, select) }
    assert { !security.testAll(select, insert) }

    assert { !security.testAll(create) }
    assert { !security.testAll(insert) }
  }

  it should "authorize operation for all permissions" in {
    assert { security.all(select, update)(1) == 1 }
    assert { security.all(update, select)(1) == 1 }

    assert { security.all(update, select, update)(1) == 1 }

    assert { security.all(select)(1) == 1 }
    assert { security.all(update)(1) == 1 }

    assert { security.all(empty)(1) == 1 }
  }

  it should "not authorize operation for all permissions" in {
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

  "RootContext" should "test permissions" in {
    assert { RootContext.test(create) }
    assert { RootContext.test(select) }
    assert { RootContext.test(update) }
    assert { RootContext.test(delete) }
    assert { RootContext.test(lupita) }
    assert { RootContext.test(root) }
    assert { RootContext.test(staff) }
    assert { RootContext.test(wheel) }
  }

  it should "authorize operation for all permissions" in {
    assert { RootContext.all(create, select, update, delete, lupita, root, staff, wheel)(1) == 1 }
  }

  it should "authorize operation for any permission" in {
    assert { RootContext.any(create, select, update, delete, lupita, root, staff, wheel)(1) == 1 }
  }
