;;; zk-threat-exchange :: rule-mutator :: tests
;;; Author: Ciprian Ștefan Pleșca

(add-to-load-path (string-append (dirname (current-filename)) "/../src"))

(use-modules (macros) (eval_sandbox))

(define pass-count 0)
(define fail-count 0)

(define (check label actual expected)
  (if (equal? actual expected)
      (begin
        (set! pass-count (+ pass-count 1))
        (display "PASS: ") (display label) (newline))
      (begin
        (set! fail-count (+ fail-count 1))
        (display "FAIL: ") (display label)
        (display " expected=") (display expected)
        (display " actual=") (display actual) (newline))))

;; --- Basic rule matching -------------------------------------------------

(define phishing-rule
  (make-rule "phishing-entropy-v1"
             '(and (gt entropy 6.0) (gt dest_rarity 0.5))
             'high))

(define malicious-event '((entropy . 6.4) (dest_rarity . 0.8)))
(define benign-event '((entropy . 3.1) (dest_rarity . 0.1)))

(check "rule matches malicious event" (matches? phishing-rule malicious-event) #t)
(check "rule does not match benign event" (matches? phishing-rule benign-event) #f)

;; --- Self-mutation: attacker lowers entropy to evade the old threshold --

(define evolved-attack-event '((entropy . 5.2) (dest_rarity . 0.8)))
(check "old rule misses evolved attack" (matches? phishing-rule evolved-attack-event) #f)

(define mutated-rule (mutate-rule phishing-rule 'entropy 4.8))
(check "mutated rule name updated" (rule-name mutated-rule) "phishing-entropy-v1-mut")
(check "mutated rule catches evolved attack" (matches? mutated-rule evolved-attack-event) #t)
(check "mutated rule still catches original attack" (matches? mutated-rule malicious-event) #t)
(check "mutated rule still ignores benign traffic" (matches? mutated-rule benign-event) #f)

;; --- Sandbox backtest gate before network-wide propagation --------------

(define labeled-samples
  (list
    (cons malicious-event #t)
    (cons evolved-attack-event #t)
    (cons benign-event #f)
    (cons '((entropy . 4.5) (dest_rarity . 0.05)) #f)))

(define old-result (backtest phishing-rule labeled-samples))
(define new-result (backtest mutated-rule labeled-samples))

(display "old-rule backtest: ") (display old-result) (newline)
(display "new-rule backtest: ") (display new-result) (newline)

(check "mutation improves accuracy" (> (cdr (assq 'accuracy new-result))
                                       (cdr (assq 'accuracy old-result)))
       #t)

(check "mutation accepted for propagation"
       (accept-mutation? phishing-rule mutated-rule labeled-samples)
       #t)

;; --- Summary --------------------------------------------------------------

(display "\n=== rule-mutator test summary ===\n")
(display pass-count) (display " passed, ")
(display fail-count) (display " failed.\n")

(if (> fail-count 0) (exit 1) (exit 0))
