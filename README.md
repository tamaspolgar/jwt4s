# JWT library for Scala
[![Build Status](https://travis-ci.org/menzus/jwt4s.svg?branch=master)](https://travis-ci.org/menzus/jwt4s)

## Creating a JWT
To create a signer you'll need `SignerSettings` and an implicit `java.time.Clock` instance:
```
implicit val clock = Clock.systemUTC
val signerSettings = SignerSettings(ConfigFactory.load("jwt.conf"))

val signer = Signer(signerSettings)

```

You can create a JWT token from subject and roles.
```
val tokenWithSubject = signer.signSubject("subject")
```
The `tokenWithSubject` has a token where the payload is:
```
{
  "iss": "issuer",
  "sub": "subject",
  "aud": "audience",
  "exp": 1,
  "iat": 0
}
```
To create a JWT with roles you need to use the `signSubjectAndRoles` method":

```
val tokenWithSubjectAndRoles = signer.signSubjectAndRoles("subject", Set("admin"))
```

The `tokenWithSubject` has a token where the payload is:
```
{
  "iss": "issuer",
  "sub": "subject",
  "aud": "audience",
  "exp": 1,
  "iat": 0,
  "roles": [
    "admin"
  ]
}
```

### Signer Settings
The project uses typesafe config, reference config:
```
jwt {
  # hmac-secret-key-base64 = "SECRET IN BASE64"
  # audience = "YOUR AUDIENCE"
  # issuer = "YOUR ISSUER"

  signer {
    # algorithm = "SIGNING ALGORITHM"

    expires-in = 1 hour
  }
}
```
Where the values are:
- jwt.hmac-secret-key-base64: the symmetric key
- jwt.audience: the audience the JWT is for
- jwt.issuer: the issuer of the JWT
- jwt.signer.algorithm: the signing algorithm
- jwt.signer.expires-in: the time period the token is valid for; default to 1 hour

# Verifies

- Settings

- ISS check
- SUB check
- AUD check
- EXP check
- IAT check
- RFP check (https://tools.ietf.org/html/draft-bradley-oauth-jwt-encoded-state-05)

- HS256
- HS384
- HS512

- Safe digest equals

- Akka HTTP directive

- Typesafe config
