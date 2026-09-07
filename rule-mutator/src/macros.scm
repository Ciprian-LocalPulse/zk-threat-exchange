;;; zk-threat-exchange :: rule-mutator :: macros.scm
;;; Author: Ciprian Ștefan Pleșca
;;;
;;; Detection rules are represented as data (an s-expression AST), not as
;;; opaque compiled matchers. Because Scheme is homoiconic, "rewriting a
;;; detection rule" is just "producing a new list" — no bytecode patching,
;;; no plugin reload, no restart. This is the property that lets the engine
;;; mutate its own logic at runtime when `heuristics-engine` (Julia) reports
;;; a statistically significant deviation in an attack pattern.
;;;
;;; A rule is represented as:
;;;   (rule <name> <predicate-sexpr> <severity>)
;;; where <predicate-sexpr> is itself an s-expression built from a small
;;; combinator vocabulary: (gt field value), (lt field value), (and ...),
;;; (or ...), (not ...).

(define-module (macros))

;; ---- Rule constructors -----------------------------------------------

(define (make-rule name predicate severity)
  (list 'rule name predicate severity))

(define (rule-name r) (list-ref r 1))
(define (rule-predicate r) (list-ref r 2))
(define (rule-severity r) (list-ref r 3))

;; ---- Predicate evaluation ----------------------------------------------
;; `event` is an association list, e.g. '((entropy . 6.4) (dest_rarity . 0.8))

(define (eval-predicate pred event)
  (cond
    ((not (pair? pred)) (error "malformed predicate" pred))
    (else
     (let ((op (car pred)))
       (cond
         ((eq? op 'gt)
          (let ((field (cadr pred)) (threshold (caddr pred)))
            (> (or (assq-ref event field) -inf.0) threshold)))
         ((eq? op 'lt)
          (let ((field (cadr pred)) (threshold (caddr pred)))
            (< (or (assq-ref event field) +inf.0) threshold)))
         ((eq? op 'and)
          (every (lambda (p) (eval-predicate p event)) (cdr pred)))
         ((eq? op 'or)
          (any (lambda (p) (eval-predicate p event)) (cdr pred)))
         ((eq? op 'not)
          (not (eval-predicate (cadr pred) event)))
         (else (error "unknown predicate operator" op)))))))

;; small local re-implementation to avoid relying on SRFI-1 availability
(define (assq-ref alist key)
  (let ((entry (assq key alist)))
    (if entry (cdr entry) #f)))

(define (every pred lst)
  (cond ((null? lst) #t)
        ((pred (car lst)) (every pred (cdr lst)))
        (else #f)))

(define (any pred lst)
  (cond ((null? lst) #f)
        ((pred (car lst)) #t)
        (else (any pred (cdr lst)))))

(define (matches? rule event)
  (eval-predicate (rule-predicate rule) event))

;; ---- Self-mutation: rewriting a rule's AST in response to drift --------
;;
;; When `heuristics-engine` observes that a malware family has shifted its
;; behavior (e.g. attackers now use a slightly lower entropy to evade a
;; fixed threshold), it reports a suggested new threshold. `mutate-rule`
;; performs the AST rewrite: it walks the predicate tree and replaces the
;; numeric literal for the given field's threshold, producing a brand new
;; rule object. The old rule is never modified in place — mutation here
;; means "derive a new generation", which keeps the process auditable
;; (every mutation is a diffable, loggable s-expression).

(define (mutate-threshold pred field new-value)
  (cond
    ((not (pair? pred)) pred)
    ((and (memq (car pred) '(gt lt)) (eq? (cadr pred) field))
     (list (car pred) field new-value))
    ((memq (car pred) '(and or))
     (cons (car pred) (map (lambda (p) (mutate-threshold p field new-value)) (cdr pred))))
    ((eq? (car pred) 'not)
     (list 'not (mutate-threshold (cadr pred) field new-value)))
    (else pred)))

(define (mutate-rule rule field new-value)
  (make-rule
    (string-append (rule-name rule) "-mut")
    (mutate-threshold (rule-predicate rule) field new-value)
    (rule-severity rule)))

(export make-rule rule-name rule-predicate rule-severity
        eval-predicate matches? mutate-rule mutate-threshold)
