# Bolster

[![Maven Central](https://img.shields.io/maven-central/v/com.github.losizm/bolster_3.svg?label=Maven%20Central)](https://central.sonatype.com/search?q=g:com.github.losizm%20a:bolster_3)

For contextual security in Scala.

## Getting Started
To get started, add **Bolster** to your library dependencies.

```scala
libraryDependencies += "com.github.losizm" %% "bolster" % "5.0.0"
```

## How It Works

**Bolster** is powered by a pair of traits: `Permission` and `SecurityContext`.

A `Permission` is identified by its name, and one or more permissions can be
applied to a restricted operation.

A `SecurityContext` establishes a pattern in which a restricted operation is
performed only if required permissions are granted; otherwise, a
`SecurityViolation` is raised.

### Security in Action

The following demonstrates how read/write access to an in-memory cache could be
implemented:

```scala
import bolster.security.{ Permission, SecurityContext, UserContext }

import scala.collection.concurrent.TrieMap

object SecureCache:
  // Define permissions to read and write cache entries
  private val getPermission = Permission("cache:get")
  private val putPermission = Permission("cache:put")

  private val cache = TrieMap[String, String](
    "gang starr"      -> "step in the arena",
    "digable planets" -> "blowout comb"
  )

  def get(key: String)(using security: SecurityContext): String =
    // Test for read permission before getting cache entry
    security(getPermission) { cache(key) }

  def put(key: String, value: String)(using security: SecurityContext): Unit =
    // Test for write permission before putting cache entry
    security(putPermission) { cache += key -> value }

// Set security context to include read permission
given SecurityContext = UserContext(Permission("cache:get"))

// Get cache entry
val classic = SecureCache.get("gang starr")

// Throw SecurityViolation because write permission is not granted
SecureCache.put("sucker mc", classic)
```

## Permission

A `Permission` is identified by its name, and you're free to implement any
naming convention.

The following defines 3 permissions, any of which could be used as a
permission for read access to an archive module:

```scala
val perm1 = Permission("archive:read")
val perm2 = Permission("module=archive; access=read")
val perm3 = Permission("GET /api/archive")
```

## Security Context

A `SecurityContext` is consulted for authorization to apply a restricted
operation. If authorized, the operation is applied; otherwise, the security
context raises a `SecurityViolation`.

`UserContext` is an implementation of a security context. It is constructed with
a set of granted permissions.

```scala
import bolster.security.{ Permission, SecurityContext, UserContext }

object BuildManager:
  private val buildPermission      = Permission("action=build")
  private val deployDevPermission  = Permission("action=deploy; env=dev")
  private val deployProdPermission = Permission("action=deploy; env=prod")

  def build(project: String)(using security: SecurityContext): Unit =
    // Test permission before building project
    security(buildPermission) {
      println(s"Build $project.")
    }

  def deployToDev(project: String)(using security: SecurityContext): Unit =
    // Test permission before deploying project
    security(deployDevPermission) {
      println(s"Deploy $project to dev environment.")
    }

  def deployToProd(project: String)(using security: SecurityContext): Unit =
    // Test permission before deploying project
    security(deployProdPermission) {
      println(s"Deploy $project to prod environment.")
    }

// Set security context to include two permissions
given SecurityContext = UserContext(
  Permission("action=build"),
  Permission("action=deploy; env=dev")
)

// Permission granted to build
BuildManager.build("my-favorite-app")

// Permission granted to deploy to dev
BuildManager.deployToDev("my-favorite-app")

// Permission not granted to deploy to prod (throw SecurityViolation)
BuildManager.deployToProd("my-favorite-app")
```

### Granting Any or All Permissions

`SecurityContext.any(Permission*)` is used to ensure that at least one of
supplied permissions is granted before an operation is applied.

`SecurityContext.all(Permission*)` is used to ensure that all supplied
permissions are granted before an operation is applied.

```scala
import bolster.security.{ Permission, SecurityContext, UserContext }

object FileManager:
  private val readOnlyPermission  = Permission("file:read-only")
  private val readWritePermission = Permission("file:read-write")
  private val encryptPermission   = Permission("file:encrypt")

  def read(fileName: String)(using security: SecurityContext): Unit =
    // Get either read-only or read-write permission before performing operation
    security.any(readOnlyPermission, readWritePermission) {
      println(s"Read $fileName.")
    }

  def encrypt(fileName: String)(using security: SecurityContext): Unit =
    // Get both read-write and encrypt permissions before performing operation
    security.all(readWritePermission, encryptPermission) {
      println(s"Encrypt $fileName.")
    }

// Set security context to include read/write permission
given SecurityContext = UserContext(Permission("file:read-write"))

// Can read via read-write permission
FileManager.read("/etc/passwd")

// Has read-write but lacks encrypt permission (throw SecurityViolation)
FileManager.encrypt("/etc/passwd")
```

### Testing Permissions

Sometimes it may be enough to simply test a permission to see whether it is
granted, and not necessarily throw a `SecurityViolation` if it isn't. That's
precisely what `SecurityContext.test(Permission)` is for. It returns `true` or
`false` based on the permission being granted or not. It's an ideal predicate to
a security filter, as demonstrated in the following:

```scala
import bolster.security.{ Permission, SecurityContext, UserContext }

object SecureMessages:
  // Define class for text message with assigned permission
  private case class Message(text: String, permission: Permission)

  private val messages = Seq(
    Message("This is a public message."   , Permission("public")),
    Message("This is a protected message.", Permission("protected")),
    Message("This is a private message."  , Permission("private"))
  )

  def list(using security: SecurityContext): Seq[String] =
    // Filter messages by testing permission
    messages.filter(msg => security.test(msg.permission)).map(_.text)

// Set security context to "public" and "protected" permissions
given SecurityContext = UserContext(Permission("public"), Permission("protected"))

// Print all accessible messages
SecureMessages.list.foreach(println)
```

### The Omnipotent Root Context

In the examples so far, we've used `UserContext`, which is a security context
with a set of granted permissions.

The other type of security context is `RootContext` for which all permissions
are granted. It's the _superuser_ security context.

`RootContext` is an object implementation, so there is only one instance. It
should be used to effectively bypass security checks.

```scala
import bolster.security.{ Permission, RootContext }

// Print all messages
SecureMessages.list(using RootContext).foreach(println)

(0 to 999999).foreach { _ =>
  // Create permission with randomly generated name
  val perm = Permission(scala.util.Random.nextString(8))

  // Assert permission is always granted
  assert(RootContext.test(perm))
}
```

Following is a more intricate example. It demonstrates how to simulate _sudo_
functionality by defining a permission to regulate access to `RootContext`.

```scala
import bolster.security.*

object sudo:
  // Define permission required for sudo
  private val sudoers = Permission("sudoers")

  def apply[T](op: SecurityContext => T)(using security: SecurityContext): T =
    // Test permission before switching to root
    security(sudoers) { op(RootContext) }

object SecureMessages:
  private case class Message(text: String, permission: Permission)

  private val messages = Seq(
    Message("This is a public message."   , Permission("public")),
    Message("This is a protected message.", Permission("protected")),
    Message("This is a private message."  , Permission("private"))
  )

  def list(using security: SecurityContext): Seq[String] =
    messages.filter(msg => security.test(msg.permission)).map(_.text)

// Set security context
given SecurityContext = UserContext(
  Permission("public"),
  Permission("protected"),
  Permission("sudoers") // Include sudo permission
)

println("Print messages in user context...")
SecureMessages.list.foreach(println)

println("Print messages in root context using sudo...")
sudo { implicit security =>
  // The implicit security shadows previous security context
  SecureMessages.list.foreach(println)
}
```

## API Documentation

See [scaladoc](https://losizm.github.io/bolster/latest/api/bolster/security.html)
for additional details.

## License
**Bolster** is licensed under the Apache License, Version 2. See [LICENSE](LICENSE)
for more information.
