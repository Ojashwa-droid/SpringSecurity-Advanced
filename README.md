# 🛡️🌿 Spring Security Advanced

Repository for advanced Spring Security concepts 🔒 including:
- **JWT Authentication & Authorization**
- **Method Level Security**
- **OAuth2 / OpenID Connect**
- **Keycloak Integration**
- **Spring Authorization Server**


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

---

### 🔑 Section 14 → OAuth2.0 Social Login (SSR-style)
This section covers: Social Login via github and facebook (in Spring MVC demo application). We integrate **OAuth2.0 social logins** (e.g., GitHub, Facebook, Google) into a Spring Security application.  

- Configuring a custom SecurityFilterChain Bean
- Bean of ClientRegistrationRepository 
- Registering and utilizing clients (github, facebook)

---

### Section 15 → Oauth2.0 with Keycloak Identity & Access Management (IAM) 🛡️

In this section, we integrate **Keycloak** as our centralized **Authentication and Authorization server**.  

🔑 What is Keycloak?
Keycloak is an open-source Identity and Access Management (IAM) solution that provides:
- Single Sign-On (SSO)  
- User federation (connect with LDAP/Active Directory)  
- Role-based access control (RBAC)  
- OAuth2, OpenID Connect (OIDC)

Instead of managing users and roles directly in our application, we **delegate all IAM responsibilities to Keycloak**.  
This makes our backend application act as a **Resource Server**, while Keycloak plays the role of **Authorization Server**.  


## ⚙️ How It Works in my Project
1. **Keycloak Server Setup**  
   - A realm is created in Keycloak (e.g., `my-app-realm`).  
   - Clients are registered in the realm (e.g., `postman-client`).  
   - Users are created/registered and roles are defined and assigned to users.  

2. **Spring Boot Integration**  
   - We configure our backend as a **Resource Server**.  
   - It validates JWT tokens issued by Keycloak (opaque tokens are kept as a option as well) 
   - Access to APIs is controlled based on roles/permissions defined in Keycloak and authroized in our resource server (SprinngBoot Application).  

3. **Authentication Flow**  
   - The user logs in through Keycloak’s login page.  
   - Keycloak authenticates the user and issues an **access token**.  
   - The token is passed in the `Authorization` header to our Spring Boot backend.  
   - The backend validates the token and grants/denies access to resources.  

## 🏗️ Benefits
- Centralized authentication & authorization  
- No need to store passwords in the backend  
- Easy integration with modern security standards (OAuth2, OIDC)  
- Supports enterprise features like SSO and user federation  

✅ With Keycloak, our application is now **enterprise-ready** with secure, standards-based Identity and Access Management.  

# Below is a screenshot of implementing MFA (Multi-factor authentication) in the project
<img width="800" height="900" alt="Screenshot 2025-08-19 112952" src="https://github.com/user-attachments/assets/722604cd-b71d-4fc8-b211-372c5ca7c538" />


---

## Section 16: Spring Authorization Server (SAS)

This module demonstrates the implementation of a fully functional **OAuth2 Authorization Server** using **Spring Authorization Server** and **Spring Security**.  
It issues **JWT tokens**, supports **OpenID Connect (OIDC)**, and is configured with multiple OAuth2 grant types for different kinds of clients.

### 🔑 Features
- Implements **OAuth2 Authorization Server** using Spring Authorization Server.
- Supports multiple grant types:
  - **Client Credentials** (for machine-to-machine communication).
  - **Authorization Code + Refresh Token** (for secure user login with clients like Postman or frontend apps).
  - **PKCE** (Proof Key for Code Exchange, for public clients like SPAs or mobile apps).
- **OpenID Connect (OIDC)** support enabled (`/.well-known/openid-configuration`).
- Tokens are **JWT (self-contained)**, signed with **RSA keys**.
- Custom claims (`roles`) are injected into tokens.
- Password security is enhanced with **HaveIBeenPwned API** check.
- Client details stored in-memory for simplicity (can be extended to DB).


### ⚙️ Configuration Highlights
- **Authorization Server Endpoints** → Enabled via `OAuth2AuthorizationServerConfigurer`.
- **JWK Source** → Auto-generates RSA key pair for signing tokens.
- **Registered Clients**:
  1. **Client Credentials Flow**
     - `client_id`: `ojasbankapi`  
     - `client_secret`: `VxubZgAXyyTq9lGjj3qGvWNsHtE4SqTq`
     - Scopes: `openid`, `ADMIN`, `USER`
  2. **Authorization Code + Refresh Token Flow**
     - `client_id`: `ojasbankclient`  
     - Redirect URI: `https://oauth.pstmn.io/v1/callback`
     - Scopes: `openid`, `email`
  3. **PKCE (Public Client)**
     - `client_id`: `ojaspublicclient`  
     - PKCE enabled (`requireProofKey=true`)
     - Redirect URI: `https://oauth.pstmn.io/v1/callback`
     - 
### 📌 Endpoints
Once the server is running, visit:

- **Discovery Document (OIDC metadata):**  http://localhost:9000/.well-known/openid-configuration
- **Authorization Endpoint:**  http://localhost:9000/oauth2/authorize
- **Token Endpoint:**  http://localhost:9000/oauth2/token
- **JWK Set Endpoint (public keys):**  http://localhost:9000/oauth2/jwks


## Following is an access token of the jwt token format (Self Contained) generated by the auth server built by the Spring Authorization Server
<img width="800" height="900" alt="image" src="https://github.com/user-attachments/assets/bb889469-3ef6-4902-9c1e-b64b17ab7a09" />

---
## 👨‍💻 Author
**Ojashwa Tripathi**  
Backend Development | Java, Spring Boot, Spring Security & Spring Authorization Server | Exploring Spring 
- 🔗 [GitHub](https://github.com/Ojashwa-droid) | [LinkedIn](https://www.linkedin.com/in/ojashwa-tripathi)









