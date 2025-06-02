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

(define-read-only (get-certificate (certificate-id uint))
    (ok (map-get? certificates {certificate-id: certificate-id}))
)

(define-read-only (get-student-certificates (student-id (string-ascii 64)))
    (ok (map-get? student-certificates {student-id: student-id}))
)

(define-read-only (verify-institution (institution-principal principal))
    (ok (map-get? institutions {institution-principal: institution-principal}))
)