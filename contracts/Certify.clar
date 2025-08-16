(define-data-var admin principal tx-sender)

(define-map certificates
    { certificate-id: uint }
    {
        student-id: (string-ascii 64),
        institution: (string-ascii 64),
        course: (string-ascii 128),
        grade: (string-ascii 2),
        issue-date: uint,
        issuer: principal,
        revoked: bool
    }
)

(define-map institutions
    { institution-principal: principal }
    { 
        name: (string-ascii 64),
        verified: bool,
        active: bool
    }
)

(define-map student-certificates
    { student-id: (string-ascii 64) }
    { certificate-ids: (list 100 uint) }
)

(define-data-var certificate-counter uint u0)

(define-map verification-codes
    { verification-code: (string-ascii 128) }
    {
        certificate-id: uint,
        generated-at: uint,
        expires-at: uint,
        used-count: uint,
        max-uses: uint,
        active: bool,
        requester: principal
    }
)

(define-map certificate-verifications
    { certificate-id: uint }
    {
        verification-code: (string-ascii 128),
        qr-data: (string-ascii 256),
        verification-count: uint,
        last-verified: uint,
        verification-hash: (string-ascii 128)
    }
)

(define-map verification-requests
    { request-id: uint }
    {
        certificate-id: uint,
        requester: principal,
        institution: principal,
        status: (string-ascii 16),
        requested-at: uint,
        approved-at: uint,
        verification-code: (string-ascii 128)
    }
)

(define-map verification-logs
    { log-id: uint }
    {
        certificate-id: uint,
        verification-code: (string-ascii 128),
        verifier: principal,
        verified-at: uint,
        verification-result: bool,
        verification-details: (string-ascii 256)
    }
)

(define-data-var verification-request-counter uint u0)
(define-data-var verification-log-counter uint u0)
(define-constant VERIFICATION_EXPIRY_BLOCKS u1440)

(define-map skills-registry
    { skill-id: uint }
    {
        skill-name: (string-ascii 64),
        category: (string-ascii 32),
        description: (string-ascii 256),
        creator: principal,
        active: bool
    }
)

(define-map certificate-skills
    { certificate-id: uint, skill-id: uint }
    {
        proficiency-level: uint,
        hours-completed: uint,
        assessment-score: uint,
        validated: bool,
        validator: principal
    }
)

(define-map student-skill-portfolio
    { student-id: (string-ascii 64), skill-id: uint }
    {
        total-hours: uint,
        highest-proficiency: uint,
        best-score: uint,
        certificate-count: uint,
        last-updated: uint,
        progression-path: (list 10 uint)
    }
)

(define-map skill-requirements
    { requirement-id: uint }
    {
        title: (string-ascii 128),
        description: (string-ascii 256),
        required-skills: (list 20 uint),
        min-proficiency-levels: (list 20 uint),
        creator: principal,
        active: bool
    }
)

(define-map skill-endorsements
    { endorsement-id: uint }
    {
        student-id: (string-ascii 64),
        skill-id: uint,
        endorser: principal,
        endorser-title: (string-ascii 64),
        rating: uint,
        comment: (string-ascii 256),
        endorsed-at: uint
    }
)

(define-map skill-pathways
    { pathway-id: uint }
    {
        name: (string-ascii 128),
        description: (string-ascii 256),
        skill-sequence: (list 15 uint),
        min-levels: (list 15 uint),
        total-hours: uint,
        creator: principal,
        active: bool
    }
)

(define-data-var skill-counter uint u0)
(define-data-var requirement-counter uint u0)
(define-data-var endorsement-counter uint u0)
(define-data-var pathway-counter uint u0)

(define-public (register-institution (name (string-ascii 64)))
    (let
        (
            (caller tx-sender)
        )
        (asserts! (is-eq tx-sender (var-get admin)) (err u403))
        (asserts! (is-none (map-get? institutions {institution-principal: caller})) (err u401))
        (ok (map-set institutions
            {institution-principal: caller}
            {
                name: name,
                verified: true,
                active: true
            }
        ))
    )
)

(define-public (issue-certificate 
    (student-id (string-ascii 64))
    (course (string-ascii 128))
    (grade (string-ascii 2))
)
    (let
        (
            (caller tx-sender)
            (institution (unwrap! (map-get? institutions {institution-principal: caller}) (err u404)))
            (current-counter (var-get certificate-counter))
            (new-counter (+ current-counter u1))
        )
        (asserts! (get verified institution) (err u403))
        (asserts! (get active institution) (err u403))
        (try! (create-certificate student-id (get name institution) course grade caller current-counter))
        (var-set certificate-counter new-counter)
        (ok current-counter)
    )
)

(define-private (create-certificate 
    (student-id (string-ascii 64))
    (institution (string-ascii 64))
    (course (string-ascii 128))
    (grade (string-ascii 2))
    (issuer principal)
    (certificate-id uint)
)
    (begin
        (map-set certificates
            {certificate-id: certificate-id}
            {
                student-id: student-id,
                institution: institution,
                course: course,
                grade: grade,
                issue-date: stacks-block-height,
                issuer: issuer,
                revoked: false
            }
        )
        (match (map-get? student-certificates {student-id: student-id})
            prev-certs (map-set student-certificates
                {student-id: student-id}
                {certificate-ids: (unwrap! (as-max-len? (append (get certificate-ids prev-certs) certificate-id) u100) (err u500))}
            )
            (map-set student-certificates
                {student-id: student-id}
                {certificate-ids: (list certificate-id)}
            )
        )
        (ok true)
    )
)

(define-public (revoke-certificate (certificate-id uint))
    (let
        (
            (caller tx-sender)
            (certificate (unwrap! (map-get? certificates {certificate-id: certificate-id}) (err u404)))
        )
        (asserts! (is-eq (get issuer certificate) caller) (err u403))
        (ok (map-set certificates
            {certificate-id: certificate-id}
            (merge certificate {revoked: true})
        ))
    )
)

(define-public (generate-verification-code (certificate-id uint) (max-uses uint))
    (let
        (
            (caller tx-sender)
            (certificate (unwrap! (map-get? certificates {certificate-id: certificate-id}) (err u404)))
            (institution (unwrap! (map-get? institutions {institution-principal: caller}) (err u404)))
            (current-block stacks-block-height)
            (expires-at (+ current-block VERIFICATION_EXPIRY_BLOCKS))
            (verification-code (create-simple-hash certificate-id current-block))
            (qr-data (create-qr-string certificate-id verification-code))
            (verification-hash (create-hash-string certificate-id verification-code current-block))
        )
        (asserts! (get verified institution) (err u403))
        (asserts! (get active institution) (err u403))
        (asserts! (is-eq (get issuer certificate) caller) (err u403))
        (asserts! (not (get revoked certificate)) (err u402))
        (asserts! (> max-uses u0) (err u400))
        (asserts! (<= max-uses u1000) (err u400))
        (unwrap-panic (store-verification-code verification-code certificate-id current-block expires-at max-uses caller))
        (unwrap-panic (store-certificate-verification certificate-id verification-code qr-data verification-hash))
        (ok verification-code)
    )
)

(define-public (verify-certificate (verification-code (string-ascii 128)))
    (let
        (
            (caller tx-sender)
            (current-block stacks-block-height)
            (code-data (unwrap! (map-get? verification-codes {verification-code: verification-code}) (err u404)))
            (certificate-id (get certificate-id code-data))
            (certificate (unwrap! (map-get? certificates {certificate-id: certificate-id}) (err u404)))
            (log-id (var-get verification-log-counter))
            (new-log-id (+ log-id u1))
        )
        (asserts! (get active code-data) (err u403))
        (asserts! (< current-block (get expires-at code-data)) (err u401))
        (asserts! (< (get used-count code-data) (get max-uses code-data)) (err u402))
        (asserts! (not (get revoked certificate)) (err u402))
        (try! (increment-verification-usage verification-code))
        (try! (log-verification certificate-id verification-code caller current-block log-id))
        (var-set verification-log-counter new-log-id)
        (ok certificate)
    )
)

(define-public (request-verification-access (certificate-id uint) (reason (string-ascii 128)))
    (let
        (
            (caller tx-sender)
            (certificate (unwrap! (map-get? certificates {certificate-id: certificate-id}) (err u404)))
            (institution-principal (get issuer certificate))
            (request-id (var-get verification-request-counter))
            (new-request-id (+ request-id u1))
        )
        (asserts! (not (get revoked certificate)) (err u402))
        (asserts! (> (len reason) u0) (err u400))
        (map-set verification-requests
            {request-id: request-id}
            {
                certificate-id: certificate-id,
                requester: caller,
                institution: institution-principal,
                status: "pending",
                requested-at: stacks-block-height,
                approved-at: u0,
                verification-code: ""
            }
        )
        (var-set verification-request-counter new-request-id)
        (ok request-id)
    )
)

(define-public (approve-verification-request (request-id uint) (max-uses uint))
    (let
        (
            (caller tx-sender)
            (request (unwrap! (map-get? verification-requests {request-id: request-id}) (err u404)))
            (certificate-id (get certificate-id request))
            (institution (unwrap! (map-get? institutions {institution-principal: caller}) (err u404)))
            (verification-code (create-simple-hash certificate-id stacks-block-height))
        )
        (asserts! (get verified institution) (err u403))
        (asserts! (get active institution) (err u403))
        (asserts! (is-eq (get institution request) caller) (err u403))
        (asserts! (is-eq (get status request) "pending") (err u402))
        (asserts! (> max-uses u0) (err u400))
        (asserts! (<= max-uses u100) (err u400))
        (map-set verification-requests
            {request-id: request-id}
            (merge request {
                status: "approved",
                approved-at: stacks-block-height,
                verification-code: verification-code
            })
        )
        (ok verification-code)
    )
)

(define-public (revoke-verification-code (verification-code (string-ascii 128)))
    (let
        (
            (caller tx-sender)
            (code-data (unwrap! (map-get? verification-codes {verification-code: verification-code}) (err u404)))
            (certificate-id (get certificate-id code-data))
            (certificate (unwrap! (map-get? certificates {certificate-id: certificate-id}) (err u404)))
        )
        (asserts! (is-eq (get issuer certificate) caller) (err u403))
        (asserts! (get active code-data) (err u402))
        (ok (map-set verification-codes
            {verification-code: verification-code}
            (merge code-data {active: false})
        ))
    )
)

(define-private (create-simple-hash (certificate-id uint) (block-num uint))
    (let
        (
            (hash-input (concat "CERT" (concat (if (> certificate-id u9) "X" "Y") (if (> block-num u1000) "A" "B"))))
            (hash-result (sha256 (unwrap-panic (to-consensus-buff? hash-input))))
        )
        (bytes-to-hex-string (unwrap-panic (slice? hash-result u0 u32)))
    )
)

(define-private (create-qr-string (certificate-id uint) (verification-code (string-ascii 128)))
    (concat (concat "CERT:" (if (> certificate-id u9) "X" "Y")) (concat ":CODE:" verification-code))
)

(define-private (create-hash-string (certificate-id uint) (verification-code (string-ascii 128)) (timestamp uint))
    (let
        (
            (hash-input (concat (concat (if (> certificate-id u9) "X" "Y") verification-code) (if (> timestamp u1000) "A" "B")))
            (hash-result (sha256 (unwrap-panic (to-consensus-buff? hash-input))))
        )
        (bytes-to-hex-string (unwrap-panic (slice? hash-result u0 u32)))
    )
)

(define-private (store-verification-code (verification-code (string-ascii 128)) (certificate-id uint) (generated-at uint) (expires-at uint) (max-uses uint) (requester principal))
    (begin
        (map-set verification-codes
            {verification-code: verification-code}
            {
                certificate-id: certificate-id,
                generated-at: generated-at,
                expires-at: expires-at,
                used-count: u0,
                max-uses: max-uses,
                active: true,
                requester: requester
            }
        )
        (ok true)
    )
)

(define-private (store-certificate-verification (certificate-id uint) (verification-code (string-ascii 128)) (qr-data (string-ascii 256)) (verification-hash (string-ascii 128)))
    (begin
        (map-set certificate-verifications
            {certificate-id: certificate-id}
            {
                verification-code: verification-code,
                qr-data: qr-data,
                verification-count: u0,
                last-verified: u0,
                verification-hash: verification-hash
            }
        )
        (ok true)
    )
)

(define-private (increment-verification-usage (verification-code (string-ascii 128)))
    (let
        (
            (code-data (unwrap! (map-get? verification-codes {verification-code: verification-code}) (err u404)))
            (new-used-count (+ (get used-count code-data) u1))
        )
        (map-set verification-codes
            {verification-code: verification-code}
            (merge code-data {used-count: new-used-count})
        )
        (ok true)
    )
)

(define-private (log-verification (certificate-id uint) (verification-code (string-ascii 128)) (verifier principal) (verified-at uint) (log-id uint))
    (let
        (
            (certificate (unwrap! (map-get? certificates {certificate-id: certificate-id}) (err u404)))
            (verification-details (create-details-string certificate))
        )
        (map-set verification-logs
            {log-id: log-id}
            {
                certificate-id: certificate-id,
                verification-code: verification-code,
                verifier: verifier,
                verified-at: verified-at,
                verification-result: true,
                verification-details: verification-details
            }
        )
        (try! (update-verification-stats certificate-id verified-at))
        (ok true)
    )
)

(define-private (create-details-string (certificate {student-id: (string-ascii 64), institution: (string-ascii 64), course: (string-ascii 128), grade: (string-ascii 2), issue-date: uint, issuer: principal, revoked: bool}))
    (concat (concat (get institution certificate) ":") (concat (get course certificate) (concat ":" (get grade certificate))))
)

(define-private (update-verification-stats (certificate-id uint) (verified-at uint))
    (let
        (
            (verification-data (unwrap! (map-get? certificate-verifications {certificate-id: certificate-id}) (err u404)))
            (new-count (+ (get verification-count verification-data) u1))
        )
        (map-set certificate-verifications
            {certificate-id: certificate-id}
            (merge verification-data {
                verification-count: new-count,
                last-verified: verified-at
            })
        )
        (ok true)
    )
)



(define-private (bytes-to-hex-string (bytes (buff 32)))
    (let
        (
            (first-part (unwrap-panic (slice? bytes u0 u4)))
            (second-part (unwrap-panic (slice? bytes u4 u8)))
            (hex-1 (if (> (len first-part) u0) "ab" "cd"))
            (hex-2 (if (> (len second-part) u0) "ef" "gh"))
        )
        (concat hex-1 hex-2)
    )
)

(define-read-only (get-certificate (certificate-id uint))
    (ok (map-get? certificates {certificate-id: certificate-id}))
)

(define-read-only (get-student-certificates (student-id (string-ascii 64)))
    (ok (map-get? student-certificates {student-id: student-id}))
)

(define-read-only (verify-institution (institution-principal principal))
    (ok (map-get? institutions {institution-principal: institution-principal}))
)

(define-read-only (get-verification-code-info (verification-code (string-ascii 128)))
    (ok (map-get? verification-codes {verification-code: verification-code}))
)

(define-read-only (get-certificate-verification-info (certificate-id uint))
    (ok (map-get? certificate-verifications {certificate-id: certificate-id}))
)

(define-read-only (get-verification-request (request-id uint))
    (ok (map-get? verification-requests {request-id: request-id}))
)

(define-read-only (get-verification-log (log-id uint))
    (ok (map-get? verification-logs {log-id: log-id}))
)

(define-read-only (get-verification-stats (certificate-id uint))
    (let
        (
            (verification-info (map-get? certificate-verifications {certificate-id: certificate-id}))
        )
        (ok {
            verification-count: (default-to u0 (get verification-count verification-info)),
            last-verified: (default-to u0 (get last-verified verification-info)),
            has-active-code: (is-some verification-info)
        })
    )
)

(define-public (register-skill (skill-name (string-ascii 64)) (category (string-ascii 32)) (description (string-ascii 256)))
    (let
        (
            (caller tx-sender)
            (skill-id (var-get skill-counter))
            (new-skill-id (+ skill-id u1))
            (institution (unwrap! (map-get? institutions {institution-principal: caller}) (err u404)))
        )
        (asserts! (get verified institution) (err u403))
        (asserts! (get active institution) (err u403))
        (asserts! (> (len skill-name) u0) (err u400))
        (asserts! (> (len category) u0) (err u400))
        (map-set skills-registry
            {skill-id: skill-id}
            {
                skill-name: skill-name,
                category: category,
                description: description,
                creator: caller,
                active: true
            }
        )
        (var-set skill-counter new-skill-id)
        (ok skill-id)
    )
)

(define-public (assign-certificate-skills (certificate-id uint) (skill-ids (list 10 uint)) (proficiency-levels (list 10 uint)) (hours-completed (list 10 uint)) (assessment-scores (list 10 uint)))
    (let
        (
            (caller tx-sender)
            (certificate (unwrap! (map-get? certificates {certificate-id: certificate-id}) (err u404)))
            (institution (unwrap! (map-get? institutions {institution-principal: caller}) (err u404)))
        )
        (asserts! (get verified institution) (err u403))
        (asserts! (get active institution) (err u403))
        (asserts! (is-eq (get issuer certificate) caller) (err u403))
        (asserts! (not (get revoked certificate)) (err u402))
        (asserts! (is-eq (len skill-ids) (len proficiency-levels)) (err u400))
        (asserts! (is-eq (len skill-ids) (len hours-completed)) (err u400))
        (asserts! (is-eq (len skill-ids) (len assessment-scores)) (err u400))
        (unwrap-panic (process-skill-assignments certificate-id skill-ids proficiency-levels hours-completed assessment-scores caller u0))
        (unwrap-panic (update-student-portfolio (get student-id certificate) skill-ids proficiency-levels hours-completed assessment-scores))
        (ok true)
    )
)

(define-public (create-skill-requirement (title (string-ascii 128)) (description (string-ascii 256)) (required-skills (list 20 uint)) (min-proficiency-levels (list 20 uint)))
    (let
        (
            (caller tx-sender)
            (requirement-id (var-get requirement-counter))
            (new-requirement-id (+ requirement-id u1))
            (institution (unwrap! (map-get? institutions {institution-principal: caller}) (err u404)))
        )
        (asserts! (get verified institution) (err u403))
        (asserts! (get active institution) (err u403))
        (asserts! (> (len title) u0) (err u400))
        (asserts! (is-eq (len required-skills) (len min-proficiency-levels)) (err u400))
        (asserts! (<= (len required-skills) u20) (err u400))
        (map-set skill-requirements
            {requirement-id: requirement-id}
            {
                title: title,
                description: description,
                required-skills: required-skills,
                min-proficiency-levels: min-proficiency-levels,
                creator: caller,
                active: true
            }
        )
        (var-set requirement-counter new-requirement-id)
        (ok requirement-id)
    )
)

(define-public (endorse-student-skill (student-id (string-ascii 64)) (skill-id uint) (endorser-title (string-ascii 64)) (rating uint) (comment (string-ascii 256)))
    (let
        (
            (caller tx-sender)
            (endorsement-id (var-get endorsement-counter))
            (new-endorsement-id (+ endorsement-id u1))
            (skill (unwrap! (map-get? skills-registry {skill-id: skill-id}) (err u404)))
            (institution (unwrap! (map-get? institutions {institution-principal: caller}) (err u404)))
        )
        (asserts! (get verified institution) (err u403))
        (asserts! (get active institution) (err u403))
        (asserts! (get active skill) (err u402))
        (asserts! (> (len student-id) u0) (err u400))
        (asserts! (> rating u0) (err u400))
        (asserts! (<= rating u10) (err u400))
        (map-set skill-endorsements
            {endorsement-id: endorsement-id}
            {
                student-id: student-id,
                skill-id: skill-id,
                endorser: caller,
                endorser-title: endorser-title,
                rating: rating,
                comment: comment,
                endorsed-at: stacks-block-height
            }
        )
        (var-set endorsement-counter new-endorsement-id)
        (ok endorsement-id)
    )
)

(define-public (create-skill-pathway (name (string-ascii 128)) (description (string-ascii 256)) (skill-sequence (list 15 uint)) (min-levels (list 15 uint)) (total-hours uint))
    (let
        (
            (caller tx-sender)
            (pathway-id (var-get pathway-counter))
            (new-pathway-id (+ pathway-id u1))
            (institution (unwrap! (map-get? institutions {institution-principal: caller}) (err u404)))
        )
        (asserts! (get verified institution) (err u403))
        (asserts! (get active institution) (err u403))
        (asserts! (> (len name) u0) (err u400))
        (asserts! (is-eq (len skill-sequence) (len min-levels)) (err u400))
        (asserts! (<= (len skill-sequence) u15) (err u400))
        (asserts! (> total-hours u0) (err u400))
        (map-set skill-pathways
            {pathway-id: pathway-id}
            {
                name: name,
                description: description,
                skill-sequence: skill-sequence,
                min-levels: min-levels,
                total-hours: total-hours,
                creator: caller,
                active: true
            }
        )
        (var-set pathway-counter new-pathway-id)
        (ok pathway-id)
    )
)

(define-public (check-skill-requirement-match (student-id (string-ascii 64)) (requirement-id uint))
    (let
        (
            (requirement (unwrap! (map-get? skill-requirements {requirement-id: requirement-id}) (err u404)))
            (required-skills (get required-skills requirement))
            (min-levels (get min-proficiency-levels requirement))
        )
        (asserts! (get active requirement) (err u402))
        (ok (check-skills-match student-id required-skills min-levels u0))
    )
)

(define-private (process-skill-assignments (certificate-id uint) (skill-ids (list 10 uint)) (proficiency-levels (list 10 uint)) (hours-completed (list 10 uint)) (assessment-scores (list 10 uint)) (validator principal) (index uint))
    (let
        (
            (current-skill-id (unwrap! (element-at? skill-ids index) (ok true)))
            (current-proficiency (unwrap! (element-at? proficiency-levels index) (err u400)))
            (current-hours (unwrap! (element-at? hours-completed index) (err u400)))
            (current-score (unwrap! (element-at? assessment-scores index) (err u400)))
        )
        (if (< index (len skill-ids))
            (begin
                (map-set certificate-skills
                    {certificate-id: certificate-id, skill-id: current-skill-id}
                    {
                        proficiency-level: current-proficiency,
                        hours-completed: current-hours,
                        assessment-score: current-score,
                        validated: true,
                        validator: validator
                    }
                )
                (ok true)
            )
            (ok true)
        )
    )
)

(define-private (update-student-portfolio (student-id (string-ascii 64)) (skill-ids (list 10 uint)) (proficiency-levels (list 10 uint)) (hours-completed (list 10 uint)) (assessment-scores (list 10 uint)))
    (begin
        (ok true)
    )
)



(define-private (check-skills-match (student-id (string-ascii 64)) (required-skills (list 20 uint)) (min-levels (list 20 uint)) (index uint))
    (let
        (
            (current-skill (unwrap! (element-at? required-skills index) true))
            (min-level (unwrap! (element-at? min-levels index) true))
            (student-portfolio (map-get? student-skill-portfolio {student-id: student-id, skill-id: current-skill}))
        )
        (if (< index (len required-skills))
            (match student-portfolio
                portfolio-data 
                    (>= (get highest-proficiency portfolio-data) min-level)
                false
            )
            true
        )
    )
)

(define-read-only (get-skill-info (skill-id uint))
    (ok (map-get? skills-registry {skill-id: skill-id}))
)

(define-read-only (get-certificate-skills (certificate-id uint))
    (ok (map-get? certificate-skills {certificate-id: certificate-id, skill-id: u0}))
)

(define-read-only (get-student-skill-portfolio (student-id (string-ascii 64)) (skill-id uint))
    (ok (map-get? student-skill-portfolio {student-id: student-id, skill-id: skill-id}))
)

(define-read-only (get-skill-requirement (requirement-id uint))
    (ok (map-get? skill-requirements {requirement-id: requirement-id}))
)

(define-read-only (get-skill-endorsement (endorsement-id uint))
    (ok (map-get? skill-endorsements {endorsement-id: endorsement-id}))
)

(define-read-only (get-skill-pathway (pathway-id uint))
    (ok (map-get? skill-pathways {pathway-id: pathway-id}))
)

(define-read-only (get-student-skill-summary (student-id (string-ascii 64)))
    (let
        (
            (total-skills (var-get skill-counter))
        )
        (ok {
            total-skills-acquired: u0,
            total-skills-available: total-skills,
            skill-completion-rate: u0
        })
    )
)


