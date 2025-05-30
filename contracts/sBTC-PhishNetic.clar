
;; sBTC-PhishNetic -  Anti-Phishing Smart Contract

;; Error codes
(define-constant ERR_UNAUTHORIZED_ACCESS (err u100))
(define-constant ERR_WEBSITE_ALREADY_REGISTERED (err u101))
(define-constant ERR_WEBSITE_NOT_FOUND (err u102))
(define-constant ERR_CONTRACT_PAUSED (err u103))
(define-constant ERR_INSUFFICIENT_COLLATERAL (err u104))
(define-constant ERR_COOLDOWN_PERIOD (err u105))
(define-constant ERR_EXCEEDS_LIMIT (err u106))
(define-constant ERR_TIMING_VIOLATION (err u107))
(define-constant ERR_MALFORMED_WEBSITE_ID (err u400))
(define-constant ERR_INVALID_CERTIFICATE (err u401))
(define-constant ERR_INSUFFICIENT_EVIDENCE (err u402))
(define-constant ERR_INVALID_THREAT_LEVEL (err u403))
(define-constant ERR_INVALID_SECURITY_LEVEL (err u404))
(define-constant ERR_INVALID_ADMIN_ADDRESS (err u405))

;; System constants
(define-constant COOLDOWN_PERIOD_SECONDS u86400) ;; 24 hours in seconds
(define-constant REQUIRED_COLLATERAL_AMOUNT u1000000) ;; in microSTX
(define-constant REQUIRED_MONITOR_REPUTATION u50)
(define-constant MAX_EVIDENCE_STRING_LENGTH u500)

;; Input validation functions
(define-private (validate-website-identifier (website_url (string-ascii 255)))
    (begin
        (asserts! (>= (len website_url) u3) (err "Website URL too short"))
        (asserts! (<= (len website_url) u255) (err "Website URL too long"))
        (asserts! (is-eq (index-of website_url ".") none) (err "Invalid character: ."))
        (asserts! (is-eq (index-of website_url "/") none) (err "Invalid character: /"))
        (asserts! (is-eq (index-of website_url " ") none) (err "Invalid character: space"))
        (ok true)))

(define-private (validate-security-certificate (ssl_certificate (string-ascii 50)))
    (begin
        (asserts! (>= (len ssl_certificate) u5) (err "Certificate too short"))
        (asserts! (<= (len ssl_certificate) u50) (err "Certificate too long"))
        (asserts! (is-eq (index-of ssl_certificate "<") none) (err "Invalid character: <"))
        (asserts! (is-eq (index-of ssl_certificate ">") none) (err "Invalid character: >"))
        (ok true)))

(define-private (validate-threat-evidence (phishing_evidence (string-ascii 500)))
    (begin
        (asserts! (>= (len phishing_evidence) u10) (err "Evidence documentation too short"))
        (asserts! (<= (len phishing_evidence) u500) (err "Evidence documentation too long"))
        (asserts! (is-eq (index-of phishing_evidence "<") none) (err "Invalid character: <"))
        (asserts! (is-eq (index-of phishing_evidence ">") none) (err "Invalid character: >"))
        (ok true)))

(define-private (validate-threat-severity (phishing_severity uint))
    (begin
        (asserts! (>= phishing_severity u1) (err "Threat severity too low"))
        (asserts! (<= phishing_severity u100) (err "Threat severity too high"))
        (ok true)))

(define-private (validate-security-level (protection_level uint))
    (begin
        (asserts! (>= protection_level u1) (err "Security level too low"))
        (asserts! (<= protection_level u10) (err "Security level too high"))
        (ok true)))

;; Administrative state variables
(define-data-var contract_owner principal tx-sender)
(define-data-var website_registration_fee uint u100)
(define-data-var required_threat_confirmations uint u5)
(define-data-var global_security_level uint u1)
(define-data-var contract_paused bool false)

;; Primary data structures
(define-map registered_secure_websites
    {website_url: (string-ascii 255)}
    {
        site_owner: principal,
        protection_level: (string-ascii 20),
        registration_date: uint,
        phishing_risk_score: uint,
        total_phishing_incidents: uint,
        locked_collateral: uint,
        last_security_audit_date: uint,
        ssl_certificate: (string-ascii 50)
    })

(define-map phishing_incident_reports
    {website_url: (string-ascii 255)}
    {
        reporter_address: principal,
        incident_timestamp: uint,
        phishing_evidence: (string-ascii 500),
        report_status: (string-ascii 20),
        phishing_severity: uint,
        victim_count: uint
    })

(define-map monitor_site_performance
    {monitor_address: principal, monitored_url: (string-ascii 255)}
    {
        report_count: uint,
        last_report_date: uint,
        trust_score: uint,
        staked_tokens: uint,
        verified_reports: uint
    })

(define-map website_audit_history
    {website_url: (string-ascii 255)}
    {
        audit_interval: uint,
        last_audit_date: uint,
        auditor_address: principal,
        audit_score: uint,
        compliance_status: (string-ascii 50)
    })

(define-map security_monitor_status
    {monitor_address: principal}
    {
        staked_tokens: uint,
        completed_assessments: uint,
        reputation_score: uint,
        last_active_date: uint,
        activity_status: (string-ascii 20)
    })

;; Query functions
(define-read-only (get-website-security-info (website_url (string-ascii 255)))
    (match (map-get? registered_secure_websites {website_url: website_url})
        website_data (ok website_data)
        (err ERR_WEBSITE_NOT_FOUND)))

(define-read-only (has-reported-threats (website_url (string-ascii 255)))
    (is-some (map-get? phishing_incident_reports {website_url: website_url})))

(define-read-only (get-monitor-reputation (monitor_address principal))
    (match (map-get? monitor_site_performance {monitor_address: monitor_address, monitored_url: ""})
        monitor_data (get trust_score monitor_data)
        u0))

;; Core operations
(define-public (register-secure-website 
    (website_url (string-ascii 255))
    (ssl_certificate (string-ascii 50)))
    (let (
        (current_time (unwrap-panic (get-stacks-block-info? time (- stacks-block-height u1))))
        (required_security_deposit (* REQUIRED_COLLATERAL_AMOUNT (var-get global_security_level))))

        ;; Input validation
        (asserts! (is-ok (validate-website-identifier website_url)) ERR_MALFORMED_WEBSITE_ID)
        (asserts! (is-ok (validate-security-certificate ssl_certificate)) ERR_INVALID_CERTIFICATE)
        (asserts! (is-eq tx-sender (var-get contract_owner)) ERR_UNAUTHORIZED_ACCESS)
        (asserts! (>= (stx-get-balance tx-sender) required_security_deposit) ERR_INSUFFICIENT_COLLATERAL)

        (match (map-get? registered_secure_websites {website_url: website_url})
            existing_site ERR_WEBSITE_ALREADY_REGISTERED
            (begin
                (try! (stx-transfer? required_security_deposit tx-sender (as-contract tx-sender)))
                (map-set registered_secure_websites
                    {website_url: website_url}
                    {
                        site_owner: tx-sender,
                        protection_level: "verified",
                        registration_date: current_time,
                        phishing_risk_score: u0,
                        total_phishing_incidents: u0,
                        locked_collateral: required_security_deposit,
                        last_security_audit_date: current_time,
                        ssl_certificate: ssl_certificate
                    })
                (ok true)))))

(define-public (submit-phishing-report 
    (website_url (string-ascii 255)) 
    (phishing_evidence (string-ascii 500))
    (phishing_severity uint))
    (let (
        (current_time (unwrap-panic (get-stacks-block-info? time (- stacks-block-height u1))))
        (monitor_data (default-to 
            {report_count: u0, last_report_date: u0, trust_score: u0, staked_tokens: u0, verified_reports: u0}
            (map-get? monitor_site_performance {monitor_address: tx-sender, monitored_url: website_url}))))

        ;; Input validation
        (asserts! (is-ok (validate-website-identifier website_url)) ERR_MALFORMED_WEBSITE_ID)
        (asserts! (is-ok (validate-threat-evidence phishing_evidence)) ERR_INSUFFICIENT_EVIDENCE)
        (asserts! (is-ok (validate-threat-severity phishing_severity)) ERR_INVALID_THREAT_LEVEL)
        (asserts! (not (var-get contract_paused)) ERR_CONTRACT_PAUSED)
        (asserts! (>= (get trust_score monitor_data) REQUIRED_MONITOR_REPUTATION) ERR_INSUFFICIENT_COLLATERAL)
        (asserts! (> (- current_time (get last_report_date monitor_data)) COOLDOWN_PERIOD_SECONDS) ERR_COOLDOWN_PERIOD)

        (map-set phishing_incident_reports
            {website_url: website_url}
            {
                reporter_address: tx-sender,
                incident_timestamp: current_time,
                phishing_evidence: phishing_evidence,
                report_status: "pending",
                phishing_severity: phishing_severity,
                victim_count: u1
            })

        (map-set monitor_site_performance
            {monitor_address: tx-sender, monitored_url: website_url}
            {
                report_count: (+ (get report_count monitor_data) u1),
                last_report_date: current_time,
                trust_score: (+ (get trust_score monitor_data) u5),
                staked_tokens: (get staked_tokens monitor_data),
                verified_reports: (get verified_reports monitor_data)
            })
        (ok true)))
