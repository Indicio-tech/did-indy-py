# DID Indy Driver

## Introduction

This service enables registration and resolution of DIDs using the [Indy DID Method][didindy].

### Transaction Endorsement

Indy Networks require Endorsement of transactions when the submitting Author's role is less than endorser. In test environments, this is usually worked around by granting endorser roles to DIDs through "self-serve" services, such as https://selfserve.indiciotech.io. In production or for "Main Net" networks, endorsement is often obtained through an ACA-Py instance acting as an Endorser using the `https://didcomm.org/transactions/1.0` protocol (this protocol is unfortunately not well defined outside of the implementation in ACA-Py).

This service provides a mechanism to endorse transactions from authors either manually or automatically, according to permissions assigned to the authors.

### Adoption of did:indy

Adoption of `did:indy` has been a slow process. First, the Indy Networks themselves needed upgrades to add the features `did:indy` depended on. Then, implementations needed to be updated. In implementations like ACA-Py, which already supported `did:sov`, it theoretically shouldn't have been too dramatic an alteration to achieve support for `did:indy`. However, `did:sov` in ACA-Py is influenced by years of Indy SDK-isms and oversimplifications that make supporting `did:indy` difficult.

This service is intended to be easily adopted by Indy-supporting code bases like ACA-Py to overcome many of the challenges experienced in adoption.

## Overview

This service provides an HTTP API with the following logical groups of functionality:

- [DID Registration Spec][didreg] Compatible API for creating `did:indy` DIDs
- [Universal Resolver][unires] Compatible API for resolving `did:indy` DIDs
- Creating and Submitting Transactions
- Resolving `did:indy` DIDs to DID Documents and DID URLs to AnonCreds objects
- Registering and Authenticating Transaction Authors

This service is usable as a standalone service or, through the Registration and Resolution APIs, as a driver for Universal Resolver or Universal Registrar instances.

## Endorser API

### Endorser Info

#### GET /info

Return endorser information to the author.

This endpoint is permitted for all scopes.

Response:
- `namespaces`: A list of `NamespaceInfo` objects containing the following properties:
    - `namespace` (string): the did:indy namespace of the endorser.
    - `nym` (string): the nym of the endorser.
    - `did` (string): the did of the endorser.

Example:

```json
{
    "namespaces": [
        "namespace": "indicio:test",
        "nym": "As728S9715ppSToDurKnvT",
        "did": "did:indy:indicio:test:As728S9715ppSToDurKnvT"
    ]
}
```

### Transaction Author Agreement

#### GET /taa/{namespace}

Retrieve the TAA for a given namespace.

The response is the TAA Info as obtained from the network:

- `aml` (object): the acceptance mechanism list.
- `taa` (object): the transaction author agreement. This will contain:
    - `text` (string): the text of the TAA.
    - `version` (string): the version of the TAA.
    - `digest` (string): the digest of the TAA.
- `required` (boolean): a flag indicating whether the TAA is required by this namespace.

Each transaction operation requires agreeing to the transaction author agreement when the namespace requires it. The endpoints below accept a parameter `taa` with the following properties:

- `taa` (object): the TAA accpetance object.
    - `taaDigest` (string): the digest of the TAA.
    - `mechanism` (string): the mechanism used to accept the TAA.
    - `time` (integer): a Unix timestamp representing the time of acceptance. This should be rounded to the nearest day.

### Creating and Submitting Transactions

#### POST /txn/nym

Publish a new nym.

For new nyms, the driver acts as both the endorser and the author. Additionally, the Endorser will apply validation rules (beyond what the ledger applies) to help authors avoid common mistakes, particularly in nym binding to verkey and diddocContent.

- `namespace` (string): the namespace/network in which to create the nym.
- `verkey` (string): the base58 encoded ed25519 public key associated with the nym.
- `nym` (string; optional): the nym to publish. If omitted, the driver will derive the nym based on the `verkey` and `version` parameters.
- `role` (string; optional): a string representing the role on the network. Defaults to no role (least privileged) if unset.
- `diddocContent` (string or object; optional): DID Document Content as a JSON object or a serialized JSON object. The document will be evaluated for correctness against the [DID Core specification][didcore].
- `version` (number; optional): `1` or `2` representing the nym version to use. `1` will validate the nym according to `did:sov` rules. `2` will validate according to `did:indy` rules. Defaults to `2` if unset.
- `taa` (object; optional): the taa acceptance object described in `GET /taa/{namespace}`; REQUIRED if the namespace requires TAA.

Response:

- `seqNo` (number): the sequence number of the published transaction.
- `nym` (string): the nym published.
- `verkey` (string): the published base58 encoded ed25519 public key associated with the nym.
- `role` (string): a string representing the role on the network.
- `diddocContent` (object): DID Document Content published as a JSON object. Note that the actual contents are published in the nym as a string but the response returns the deserialzed representation for convenience.
- `did` (string): the `did:indy` representation of the published nym
- `did_sov` (string): the `did:sov` representation of the published nym

Example:

```json
{
    "seqNo": 17991,
    "nym": "6arEcmUv2ZutDuEvHEtoac",
    "verkey": "43WW5eU1DLyoyFLvsjGupRvLy79mrgpPqaA7sWwjzvL6",
    "role": "101",
    "diddocContent": {
        "@context": [
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "assertionMethod": [
            "did:indy:indicio:test:6arEcmUv2ZutDuEvHEtoac#assert"
        ],
        "verificationMethod": [
            {
                "controller": "did:indy:indicio:test:6arEcmUv2ZutDuEvHEtoac",
                "id": "did:indy:indicio:test:6arEcmUv2ZutDuEvHEtoac#assert",
                "publicKeyMultibase": "z6MkwEDBwMAh5BTt4CjstEmNdvTeY2SJFZB4CFGnw88JWaXG",
                "type": "Ed25519VerificationKey2020"
            }
        ]
    },
    "did": "did:indy:indicio:test:6arEcmUv2ZutDuEvHEtoac",
    "did_sov": "did:sov:6arEcmUv2ZutDuEvHEtoac",
}
```

#### POST /txn/schema

Prepare a new schema transaction.

The schema transaction is prepared and returned to the client to prepare a signature. Once signed, the client submits the transaction to `POST /txn/schema/submit`.

Request Body:
- `schema` (object): the AnonCreds Schema object with the following properties:
    - `issuerId` (string; also accepts `issuer_id`): the DID of the issuer.
    - `attrNames` (string; also accepts `attr_names`): the attributes of the schema.
    - `name` (string): the name of the schema.
    - `version` (string): the version of the schema.
- `taa` (object; optional): the TAA acceptance object described in `GET /taa/{namespace}`; REQUIRED if the namespace requires TAA.

The response is a `TxnToSignResponse` representing a transaction to be signed by the client. This response includes the following parameters:

- `request` (string): the serialized Indy transaction request.
- `signature_input` (string): the base64 encoded bytes to be signed by the client.

The client should validate that the returned request and signature input agree with the original request submitted by the client.

#### POST /txn/schema/submit

Submit a signed schema transaction.

After independently preparing a transaction request or after using the `POST /txn/schema` endpoint, the client submits the schema transaction request to the driver to be endorsed and submitted to the network.

Request Body:
- `submitter` (string): the `did:indy` DID of the submitter
- `request` (string): the serialized transaction request.
- `signature` (string): the client's signature over the transaction request.

The driver endorses the transaction and submits it to the network and returns the following:
- `schema_id` (string): the `did:indy` DID URL for this schema.
- `indy_schema_id` (string): the Indy native schema ID for this schema.
- `registration_metadata` (object): an object containing the transaction submission result details.
- `schema_metadata` (object): an object with metadata about the schema containing the following properties:
    - `txnId` (string): transaction ID.
    - `txnTime` (integer): timestamp of when the transaction was submitted.
    - `seqNo` (integer): the sequence number of the transaction on the Indy network.

The client should validate that the returned DID URL includes the client's submitter DID. The client may also choose to independently resolve the schema from the network to verify it was published.

#### POST /txn/schema/endorse

Request endorsement of a signed schema request.

If the client wishes to publish its own transactions, the client may use this endpoint to request endorsement of a schema transaction.

Request Body:
- `submitter` (string): the DID of the submitter.
- `request` (string): the serialized transaction request.
- `signature` (string; optional): the base64 encoded signature over the request.

The driver endorses the transaction and returns the endorsed transaction:
- `request` (string): the serialized signed transaction request.

#### POST /txn/cred-def

Prepare a new credential definition transaction.

The credential definition transaction is prepared and returned to the client to prepare a signature. Once signed, the client submits the transaction to `POST /txn/cred-def/submit`.

Request Body:
- `cred_def` (object): an object containing the AnonCreds credential definition:
    - `issuerId` (string; also accepts `issuer_id`): the DID of the issuer.
    - `schemaId` (string; also accepts `schema_id`): the DID URL of the schema.
    - `type` (string): the literal string `"CL"`.
    - `tag` (string): the tag of the credential definition.
    - `value` (string): the value of the credential definition. Omitted for brevity.
- `taa` (object; optional): the TAA acceptance object described in `GET /taa/{namespace}`; REQUIRED if the namespace requires TAA.

The response is a `TxnToSignResponse` representing a transaction to be signed by the client. This response includes the following parameters:

- `request` (string): the serialized Indy transaction request.
- `signature_input` (string): the base64 encoded bytes to be signed by the client.

The client should validate that the returned request and signature input agree with the original request submitted by the client.

#### POST /txn/cred-def/submit

Submit a signed credential definition transaction.

After independently preparing a transaction request or after using the `POST /txn/cred-def` endpoint, the client submits the credential definition transaction request to the driver to be endorsed and submitted to the network.

Request Body:
- `submitter` (string): the `did:indy` DID of the submitter
- `request` (string): the serialized transaction request.
- `signature` (string): the client's signature over the transaction request.

The driver endorses the transaction and submits it to the network and returns the following:
- `cred_def_id` (string): the `did:indy` DID URL for this credential definition.
- `indy_cred_def_id` (string): the Indy native schema ID for this credential definition.
- `registration_metadata` (object): an object containing the transaction submission result details.
- `cred_def_metadata` (object): an object with metadata about the credential definition containing the following properties:
    - `txnId` (string): transaction ID.
    - `txnTime` (integer): timestamp of when the transaction was submitted.
    - `seqNo` (integer): the sequence number of the transaction on the Indy network.

The client should validate that the returned DID URL includes the client's submitter DID. The client may also choose to independently resolve the credential definition from the network to verify it was published with the expected values.

#### POST /txn/schema/endorse

Request endorsement of a signed credential definition request.

If the client wishes to publish its own transactions, the client may use this endpoint to request endorsement of a schema transaction.

Request Body:
- `submitter` (string): the DID of the submitter.
- `request` (string): the serialized transaction request.
- `signature` (string; optional): the base64 encoded signature over the request.

The driver endorses the transaction and returns the prepared transaction request:
- `request` (string): the serialized signed transaction request.

#### POST /txn/rev-reg-def

> TODO

#### POST /txn/rev-reg-def/submit

> TODO

#### POST /txn/rev-reg-def/endorse

> TODO

## Endorsement Responses Webhooks

On transaction submit operations, if the transaction is automatically endorsed, the driver will sign and submit the transaction and return a status code of `201 Created` along with the request bodies described above.

If the transaction must be manually endorsed, the driver will return the following response with status code `202 Accepted`:

- `request_id` (string): an identifier (e.g. a UUID) for this request that will be used to later report the outcome. This value MAY be the `request_id` contained in the transaction endorsement request body but the endorser MAY choose to identify the request using another value.

Example 202 Accepted response:

```
HTTP/1.1 202 Accepted
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache

{
  "request_id": "20539d62-b178-4062-9160-17ddaf53a317"
}
```

### Webhooks

#### Authentication

When the driver communicates with the client via webhook, the driver will provide an `Authorization` Header with a Bearer JWT signed by a key identified in the driver's `jkws` or in its resolved `jwks_uri`.

When transactions are not automatically endorsed (when a `202 Accepted` is received in response to a request), the client must await updates about the transaction endorsement request status.

The driver will make a `POST` request to the client's `webhook_url`, if provided at registration token generation. The request will include an `Authorization` Header with a Bearer JWT signed by a key identified in the driver's `jwks` metadata or at the specified `jwks_uri`.

The headers of the JWT will include:

- `alg` (string): this will always be `EdDSA`.
- `typ` (string): this will always be `JWT`.
- `kid` (string): the kid of the key used to sign the JWT.

The payload of the JWT will contain the following claims:

- `iss` (string): the url of the driver.
- `aud` (string): `client_id` of the client, as issued on registration (described below).
- `iat` (number): unix timestamp of token generation.
- `event` (string): the type of event being reported to the webhook; one of `challenge`, `endorsed`, or `rejected`.
- `request_id` (string): the request id reported on `202 Accepted` response for the transaction in question.

The omission of any of these fields or failure to validate against the following rules should result in a 400 Bad Request error and the client should reject the webhook as invalid.

Validation Rules:
- `iss` MUST match the driver issuer metadata, as reported in the driver info endpoint.
- `aud` MUST match the client's client_id as issued on registration.
- `iat` MUST NOT be in the future (give or take some amount of leeway).
- `request_id` MUST correspond to a request the client previously made.
- `event` MUST be one of `challenge`, `endorsed`, or `rejected`.

The Request Body will contain:
- `request_id` (string): the request id reported on `202 Accepted` response for the transaction in question.
- `event` (string): the type of event being reported to the webhook; one of `challenge`, `endorsed`, or `rejected`.

The remaining parameters are dictated by the event type. For `endorsed`:
- `txn_type` (string): the type of transaction that was published; one of `nym`, `schema`, `cred-def`, `rev-reg-def`, or `rev-reg-entry`
- `response` (object): an object matching the response on `201 Created` for the given transaction type.

For `rejected`:
- `txn_type` (string): the type of transaction that was published; one of `nym`, `schema`, `cred-def`, `rev-reg-def`, or `rev-reg-entry`

For `challenge`:
- `secret` (string): the secret to be presented to the `POST /webhook/challenge` endpoint

### Webhook Challenge

When a client is dynamically registered, a `challenge` webhook is posted to the specified webhook URL. This ensures that the client is in control of the URL.

The expected flow of the challenge is:
1. Client registers, providing the webhook URL for the first time, or updates the webhook URL
2. The driver posts a challenge webhook to the client's webhook URL

## Client Registration

Client registration is achieved by the following steps:
1. The Endorser generates a registration token
2. The token is delivered to the author (out-of-band)
3. The Author makes a request to the registration endpoint with the registration token

### Driver Metadata

The driver publishes metadata about the service using the endpoint defined by [OAuth 2.0 Authorization Server Metadata][asmeta], `/.well-known/oauth-authorization-server`.

Example response:

```http
HTTP/1.1 200 OK
Content-Type: application/json
```
```json
{
 "issuer": "https://indy-endorser.example.com",
 "token_endpoint": "https://indy-endorser.example.com/token",
 "token_endpoint_auth_methods_supported": ["private_key_jwt"],
 "grant_types_supported": ["client_credentials"],
 "jwks_uri": "https://indy-endorser.example.com/jwks.json",
 "registration_endpoint": "https://indy-endorser.example.com/register",
 "scopes_supported": ["all", "nym", "schema", "cred_def", "rev_reg_def", "rev_reg_entry"],
 "service_documentation": "http://indy-endorser.example.com/docs",
}
```


### Registration Token Generation

Generation of registration tokens must be done by authorized users only. This can be achieved a number of ways. Three mechanisms are outlined below.

#### Web UI

The Endorser Service could host an Administration Web UI. Users must be authenticated and then authorized to access the token registration function. This could be handled through direct management of users or through an external ID Provider (e.g. Keycloak, Google Enterprise, Microsoft Teams, etc.).

#### CLI

A CLI application with access to the same secrets held by the Endorser Service could be used by an administrator to generate a registration token.

#### After Presentation of a VC from a trusted Issuer

Upon presentation of a credential from a trusted Issuer, the Endorser Service could issue a registration token based on the credential.

### Usage of a Token vs a VC

Verifiable Credentials are very similar to JWTs in a number of ways. Some VCs are secured using JWTs, even.

Verifiable Credentials enable a transfer of trust from one context to another, in addition to preserving the integrity of a set of claims. This enables a credential issued as proof of an individuals privilege to operate a vehicle to be reused to prove that they are above the threshold required to purchase age restricted goods.

JWTs are a more primitive construct. It is up to the application to define their significance. In this case, the intended use of the registration token is limited to accessing the registration endpoint. It would be inappropriate to reuse the token in any other context. It would just add unnecessary complexity to the token to incorporate requirements of one of the many VC Formats. Therefore, the registration token is deliberately just a simple JWT and not a VC.

### Registration Token

The Registration Token is a JWT secured by either HS256 (hmac) or an asymmetric signature. When using HS256, the Endorser service itself must be the issuer of the token. When an asymmetric signature is used, the token must be signed by a service trusted by the Endorser (e.g. through service configuration).

The token payload must contain the following claims:

- `iss`: The URL of the Issuer (Endorser or another trusted service)
- `aud`: MUST be the URL of the Endorser
- `iat`: Time of issuance
- `exp`: Expiration time. Service should default to a reasonable time frame. 1 hour is suggested.
- `ver`: An integer representing the version of this registration token. `1` for this version.
- `auto_endorse`: An object with the following keys:
    - `nym_new`: An integer value indicating the number of new nyms the endorser will automatically endorse from the author. Defaults to `1` if unset or `auto_endorse` is unset.
    - `nym_update`: A boolean value indicating whether the endorser will automatically endorse nym update transactions, excluding role changes, from the author. Defaults to `true` if unset or `auto_endorse` is unset.
    - `nym_role_change`: A boolean value indicating whether the endorser will automatically endorse nym update transactions updating roles from the author. This essentially covers nym transactions updating verkey and/or diddocContent. Defaults to `false` if unset or `auto_endorse` is unset.
    - `schema`: A boolean value indicating whether the endorser will automatically endorse schema transactions from the author. Defaults to `false` if unset or `auto_endorse` is unset.
    - `cred_def`: A boolean value indicating whether the endorser will automatically endorse cred_def transactions from the author. Defaults to `true` if unset or `auto_endorse` is unset.
    - `rev_reg_def`: A boolean value indicating whether the endorser will automatically endorse rev_reg_def transactions from the author. Defaults to `true` if unset or `auto_endorse` is unset.
    - `rev_reg_entry`: A boolean value indicating whether the endorser will automatically endorse rev_reg_entry transactions from the author. Defaults to `true` if unset or `auto_endorse` is unset.
- `permitted_roles`: A list of roles permitted for nyms submitted by the author. Defaults to an empty list if unset, indicating the author is only permitted to create nyms with the least privileged role on the network, usually called the "author" role.
- `txn_webhook_url`: The URL at which the author will receive webhooks regarding transaction requests.

Example payload:

```json
{
    "iss": "https://indy-endorser.example.com",
    "aud": "https://indy-endorser.example.com",
    "iat": 1728060682,
    "exp": 1728064282,
    "ver": 1,
    "auto_endorse": {
        "nym_new": 1,
        "nym_update": true,
        "schema": true,
        "cred_def": true,
    },
    "txn_webhook_url": "https://indy-author.example.com",
}
```

#### Binding the registration token to a sender

When a public key is known for the author at the time of token generation, the token MAY be sender-constrained. Sender-constrained token payloads contain the following claim:

- `cnf`: Token confirmation claim as defined in [RFC 7800][popsem]. It MUST contain `jkt` confirmation method defined in [RFC 9449][dpop]. This claim is a JWK Thumbprint of the author's public key that they will use to later authenticate themselves to the Endorser as the intended sender of the token.

The resulting token is considered a DPoP token (rather than a Bearer token).

When the token is not sender-constrained, the token is a Bearer token.

#### Token Delivery

The Token is delivered to the Author out-of-band. The exact mechanism is out of scope for this document.

### Registration Endpoint

Upon receiving a Registration Token, the Author makes a request to the registration endpoint. The registration endpoint is a [Dynamic Client Registration][dynclient] Endpoint as defined by RFC 7591.

The Endorser expects the following client metadata properties:

- `client_name` (string): The author's name

#### Registration Request

If the registration token is sender-constrained, the request MUST use `DPoP` authorization and include a proof of possession in the `DPoP` header.

Example DPoP Request:

```http
POST /register
Host: indy-endorser.example.com 
Content-Type: application/json
Authorization: DPoP <registration token>
DPoP: <base64url encoded DPoP token>
```
```json
{
    "client_name": "My Example Author",
}
```

Both the registration token and the DPoP token must be verified.

If the registration token is a unconstrained, the request MUST use `Bearer` authorization.

Example Bearer Request:

```http
POST /register
Host: indy-endorser.example.com 
Content-Type: application/json
Authorization: Bearer <registration token>
```
```json
{
    "client_name": "My Example Author",
}
```

#### Registration Response

The registration response contains the `client_id` and `client_secret` that will be used by this client to authenticate itself to the endorser.

```http
HTTP/1.1 201 Created
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache
```
```json
{
  "client_id": "s6BhdRkqt3",
  "client_secret": "cf136dc3c1fc93f31185e5885805d",
  "client_id_issued_at": 2893256800,
  "client_secret_expires_at": 2893276800,
  "grant_types": ["client_credentials"],
  "client_name": "My Example Author",
  "txn_webhook_url": "https://example.author.com"
}
```

## Client Authentication

The client authenticates to the endorser using the `client_credentials` grant type defined in [OAuth 2.0][oauth2].

### Token Request

To authenticate to the endorser, the client uses `Basic` authorization. Basic authorization expects the Base64 URL encoding of `client_id:client_secret`, replacing `client_id` and `client_secret` with the values obtained during author registration.

Example token request:

```http
POST /token HTTP/1.1
Host: server.example.com
Authorization: Basic <base64url encoded client_id:client_secret>
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
scope=<optional scopes>
```

See Token Scopes below for values for scope.

### Token Response

The response is a JWT Access Token to be used at the Endorser API Endpoints defined below.

#### Scopes

- `all`: The token can be used to request endorsement of all transaction types
- `nym`: Authorizes the token to request endorsement of nym transactions
- `schema`: Authorizes the token to request endorsement of schema transactions
- `cred_def`: Authorizes the token to request endorsement of cred def transactions
- `rev_reg_def`: Authorizes the token to request endorsement of rev reg def transactions
- `rev_reg_entry`: Authorizes the token to request endorsement of rev reg entry transactions

It is in the best interest of the client to minimize the scopes requested to the intended operations only.

### Updating Author Info
#### PUT /author

Update details about the author

- `txn_webhook_url` (string): new webhook URL to which transaction webhooks should be sent.

---

## References

- [Indy DID Method Specification][didindy]
- [DID Registration Specification][didreg]
- [Universal Resolver][unires]
- [Decentralized Identifiers (DIDs) v1.0][didcore]
- [RFC 6749: OAuth 2.0 Authorization Framework][oauth2]
- [RFC 7591: Dynamic Client Registration][dynclient]
- [RFC 9449: OAuth 2.0 Demonstrating Proof of Possession][dpop]
- [RFC 7800: OAuth 2.0 Proof-of-Possession Key Semantics for JSON Web Tokens][popsem]
- [RFC 8414: OAuth 2.0 Authorization Server Metadata][asmeta]


[didindy]: https://hyperledger.github.io/indy-did-method/
[didreg]: https://identity.foundation/did-registration/
[unires]: https://github.com/decentralized-identity/universal-resolver/
[didcore]: https://www.w3.org/TR/did-core/
[oauth2]: https://datatracker.ietf.org/doc/html/rfc6749
[dpop]: https://datatracker.ietf.org/doc/html/rfc9449
[popsem]: https://datatracker.ietf.org/doc/html/rfc7800
[asmeta]: https://datatracker.ietf.org/doc/html/rfc8414
[dynclient]: https://datatracker.ietf.org/doc/html/rfc7591
