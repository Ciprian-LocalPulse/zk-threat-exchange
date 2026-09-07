;;; zk-threat-exchange :: rule-mutator :: eval_sandbox.scm
;;; Author: Ciprian Ștefan Pleșca
;;;
;;; Before a mutated rule is broadcast to the network, it must prove it does
;;; not regress against a held-out set of known-benign and known-malicious
;;; sample events. This module provides an isolated backtest harness: no
;;; new rule reaches the gossip network without passing through here first.

(define-module (eval_sandbox)
  #:use-module (macros))

;; A labeled sample: (event . expected-verdict) where expected-verdict is #t
;; (should match / is malicious) or #f (should not match / is benign).

(define (backtest rule labeled-samples)
  (let loop ((samples labeled-samples) (correct 0) (total 0) (false-positives 0) (false-negatives 0))
    (if (null? samples)
        (list
          (cons 'total total)
          (cons 'correct correct)
          (cons 'accuracy (if (= total 0) 0.0 (/ correct total)))
          (cons 'false-positives false-positives)
          (cons 'false-negatives false-negatives))
        (let* ((sample (car samples))
               (event (car sample))
               (expected (cdr sample))
               (actual (matches? rule event))
               (is-correct (eq? actual expected))
               (fp (and actual (not expected)))
               (fn (and (not actual) expected)))
          (loop (cdr samples)
                (if is-correct (+ correct 1) correct)
                (+ total 1)
                (if fp (+ false-positives 1) false-positives)
                (if fn (+ false-negatives 1) false-negatives))))))

;; A mutated rule is only accepted for network-wide propagation if:
;;   1. Its accuracy on the backtest set is >= the accuracy of the rule it
;;      replaces (no silent regressions), AND
;;   2. It introduces zero new false positives beyond a configured tolerance.
;;
;; This is deliberately conservative: better to miss a rule generation than
;; to auto-propagate a rule that starts flagging legitimate traffic across
;; every connected enterprise node.

(define* (accept-mutation? old-rule new-rule labeled-samples #:optional (fp-tolerance 0))
  (let* ((old-result (backtest old-rule labeled-samples))
         (new-result (backtest new-rule labeled-samples))
         (old-acc (cdr (assq 'accuracy old-result)))
         (new-acc (cdr (assq 'accuracy new-result)))
         (new-fp (cdr (assq 'false-positives new-result))))
    (and (>= new-acc old-acc)
         (<= new-fp fp-tolerance))))

(export backtest accept-mutation?)
