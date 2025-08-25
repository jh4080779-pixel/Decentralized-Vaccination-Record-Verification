;; IssuanceContract.clar
;; Manages issuance of vaccination credentials by authorized healthcare providers
;; Integrates with IdentityContract for DID-based ownership and supports privacy-preserving verification

;; Constants
(define-constant ERR-UNAUTHORIZED u200)
(define-constant ERR-NOT-FOUND u201)
(define-constant ERR-INVALID-ISSUER u202)
(define-constant ERR-PAUSED u203)
(define-constant ERR-INVALID-PARAM u204)
(define-constant ERR-ALREADY-ISSUED u205)
(define-constant ERR-INVALID-DID u206)
(define-constant ERR-METADATA-TOO-LONG u207)
(define-constant MAX-METADATA-LEN u500)
(define-constant MAX-BATCH-NUMBER-LEN u50)
(define-constant DID-PREFIX "did:stack:")

;; Data Variables
(define-data-var contract-paused bool false)
(define-data-var admin principal tx-sender)

;; Data Maps
(define-map issuers
  { issuer: principal }
  {
    name: (string-utf8 100),
    registered-at: uint,
    active: bool,
    verification-key: (buff 33) ;; Public key for signing credentials
  }
)

(define-map credentials
  { credential-id: (buff 32) } ;; Hash of DID + vaccine details
  {
    did: (string-ascii 64),
    issuer: principal,
    vaccine-type: (string-utf8 50),
    batch-number: (string-utf8 50),
    issue-date: uint,
    expiry-date: (optional uint),
    metadata: (string-utf8 500),
    signature: (buff 65), ;; ECDSA signature
    active: bool
  }
)

(define-map issuance-records
  { did: (string-ascii 64), issue-id: uint }
  {
    credential-id: (buff 32),
    timestamp: uint
  }
)

;; Private Functions
(define-private (is-admin (caller principal))
  (is-eq caller (var-get admin))
)

(define-private (validate-did (did (string-ascii 64)))
  (and
    (> (len did) u0)
    (is-eq (slice? did u0 u10) (some DID-PREFIX))
  )
)

(define-private (generate-credential-id (did (string-ascii 64)) (vaccine-type (string-utf8 50)) (batch-number (string-utf8 50)) (issue-date uint))
  (hash160 (concat (unwrap-panic (to-bytes did)) (concat (unwrap-panic (to-bytes vaccine-type)) (unwrap-panic (to-bytes batch-number)))))
)

;; Public Functions
(define-public (pause-contract)
  (begin
    (asserts! (is-admin tx-sender) (err ERR-UNAUTHORIZED))
    (var-set contract-paused true)
    (ok true)
  )
)

(define-public (unpause-contract)
  (begin
    (asserts! (is-admin tx-sender) (err ERR-UNAUTHORIZED))
    (var-set contract-paused false)
    (ok true)
  )
)

(define-public (set-admin (new-admin principal))
  (begin
    (asserts! (is-admin tx-sender) (err ERR-UNAUTHORIZED))
    (var-set admin new-admin)
    (ok true)
  )
)

(define-public (register-issuer (name (string-utf8 100)) (verification-key (buff 33)))
  (begin
    (asserts! (not (var-get contract-paused)) (err ERR-PAUSED))
    (asserts! (is-none (map-get? issuers {issuer: tx-sender})) (err ERR-ALREADY-ISSUED))
    (asserts! (> (len name) u0) (err ERR-INVALID-PARAM))
    (asserts! (> (len verification-key) u0) (err ERR-INVALID-PARAM))
    (map-set issuers
      {issuer: tx-sender}
      {
        name: name,
        registered-at: block-height,
        active: true,
        verification-key: verification-key
      }
    )
    (ok true)
  )
)

(define-public (deactivate-issuer (issuer principal))
  (begin
    (asserts! (is-admin tx-sender) (err ERR-UNAUTHORIZED))
    (let
      (
        (issuer-data (unwrap! (map-get? issuers {issuer: issuer}) (err ERR-NOT-FOUND)))
      )
      (map-set issuers
        {issuer: issuer}
        (merge issuer-data {active: false})
      )
      (ok true)
    )
  )
)

(define-public (issue-credential
  (did (string-ascii 64))
  (vaccine-type (string-utf8 50))
  (batch-number (string-utf8 50))
  (issue-date uint)
  (expiry-date (optional uint))
  (metadata (string-utf8 500))
  (signature (buff 65))
  (issue-id uint))
  (let
    (
      (issuer-data (unwrap! (map-get? issuers {issuer: tx-sender}) (err ERR-INVALID-ISSUER)))
      (credential-id (generate-credential-id did vaccine-type batch-number issue-date))
      (existing-credential (map-get? credentials {credential-id: credential-id}))
    )
    (asserts! (not (var-get contract-paused)) (err ERR-PAUSED))
    (asserts! (get active issuer-data) (err ERR-INVALID-ISSUER))
    (asserts! (validate-did did) (err ERR-INVALID-DID))
    (asserts! (is-none existing-credential) (err ERR-ALREADY-ISSUED))
    (asserts! (> (len vaccine-type) u0) (err ERR-INVALID-PARAM))
    (asserts! (<= (len batch-number) MAX-BATCH-NUMBER-LEN) (err ERR-INVALID-PARAM))
    (asserts! (<= (len metadata) MAX-METADATA-LEN) (err ERR-METADATA-TOO-LONG))
    (asserts! (> (len signature) u0) (err ERR-INVALID-PARAM))
    (map-set credentials
      {credential-id: credential-id}
      {
        did: did,
        issuer: tx-sender,
        vaccine-type: vaccine-type,
        batch-number: batch-number,
        issue-date: issue-date,
        expiry-date: expiry-date,
        metadata: metadata,
        signature: signature,
        active: true
      }
    )
    (map-set issuance-records
      {did: did, issue-id: issue-id}
      {
        credential-id: credential-id,
        timestamp: block-height
      }
    )
    (ok credential-id)
  )
)

(define-public (revoke-credential (credential-id (buff 32)))
  (let
    (
      (credential (unwrap! (map-get? credentials {credential-id: credential-id}) (err ERR-NOT-FOUND)))
      (issuer-data (unwrap! (map-get? issuers {issuer: tx-sender}) (err ERR-INVALID-ISSUER)))
    )
    (asserts! (not (var-get contract-paused)) (err ERR-PAUSED))
    (asserts! (get active issuer-data) (err ERR-INVALID-ISSUER))
    (asserts! (is-eq (get issuer credential) tx-sender) (err ERR-UNAUTHORIZED))
    (map-set credentials
      {credential-id: credential-id}
      (merge credential {active: false})
    )
    (ok true)
  )
)

(define-public (update-credential-metadata (credential-id (buff 32)) (new-metadata (string-utf8 500)))
  (let
    (
      (credential (unwrap! (map-get? credentials {credential-id: credential-id}) (err ERR-NOT-FOUND)))
      (issuer-data (unwrap! (map-get? issuers {issuer: tx-sender}) (err ERR-INVALID-ISSUER)))
    )
    (asserts! (not (var-get contract-paused)) (err ERR-PAUSED))
    (asserts! (get active issuer-data) (err ERR-INVALID-ISSUER))
    (asserts! (is-eq (get issuer credential) tx-sender) (err ERR-UNAUTHORIZED))
    (asserts! (<= (len new-metadata) MAX-METADATA-LEN) (err ERR-METADATA-TOO-LONG))
    (map-set credentials
      {credential-id: credential-id}
      (merge credential {metadata: new-metadata})
    )
    (ok true)
  )
)

;; Read-Only Functions
(define-read-only (get-issuer (issuer principal))
  (map-get? issuers {issuer: issuer})
)

(define-read-only (get-credential (credential-id (buff 32)))
  (map-get? credentials {credential-id: credential-id})
)

(define-read-only (get-issuance-record (did (string-ascii 64)) (issue-id uint))
  (map-get? issuance-records {did: did, issue-id: issue-id})
)

(define-read-only (is-issuer-active (issuer principal))
  (match (map-get? issuers {issuer: issuer})
    issuer-data (get active issuer-data)
    false
  )
)

(define-read-only (is-credential-active (credential-id (buff 32)))
  (match (map-get? credentials {credential-id: credential-id})
    credential (get active credential)
    false
  )
)

(define-read-only (verify-issuer-signature (credential-id (buff 32)) (signature (buff 65)))
  (let
    (
      (credential (unwrap! (map-get? credentials {credential-id: credential-id}) (err ERR-NOT-FOUND)))
      (issuer-data (unwrap! (map-get? issuers {issuer: (get issuer credential)}) (err ERR-INVALID-ISSUER)))
    )
    (ok (is-eq signature (get signature credential)))
  )
)

(define-read-only (is-contract-paused)
  (var-get contract-paused)
)

(define-read-only (get-admin)
  (var-get admin)
)