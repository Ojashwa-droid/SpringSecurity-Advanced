# 🛡️🌿 Spring Security Advanced

Repository for advanced Spring Security concepts including:
- **JWT Authentication & Authorization**
- **Method Level Security**
- **OAuth2 / OpenID Connect**
- **Keycloak Integration**

## Sections

### Section 11 → JWT
This section covers:
- Generating JWT tokens (JwtTokenGeneratorFilter)
- Validating tokens (JwtTokenValidatorFilter)
- Integrating JWT with Spring Security filters
- Securing REST APIs with JWT (Till now: BasicAuthN + Jwt)
- Publishing Authentication Manager for custom authentication (Without BasicAuthN, credentials in requestBody for safer authN) 

**Folder:** `section11/springsecsection11`

---

### Section 12 → Method Level Security
This section covers: 1. Invocation Authorization 2. Filtering Authorization
- `@PreAuthorize` and `@PostAuthorize`
- Role-based access control on methods
- Using SpEL (Spring Expression Language) for fine-grained security rules
- Combining method security with global security configurations
- `@PreFilter` and `@PostFilter`
- Controlling what specific parameters are sent and reieved from the annotated method

**Folder:** `section12/springsecsection12`


