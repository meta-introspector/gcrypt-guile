;;; guile-gcrypt --- crypto tooling for guile
;;; Copyright © 2019 Ludovic Courtès <ludo@gnu.org>
;;;
;;; This file is part of guile-gcrypt.
;;;
;;; guile-gcrypt is free software; you can redistribute it and/or modify it
;;; under the terms of the GNU General Public License as published by
;;; the Free Software Foundation; either version 3 of the License, or
;;; (at your option) any later version.
;;;
;;; guile-gcrypt is distributed in the hope that it will be useful, but
;;; WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
;;; General Public License for more details.
;;;
;;; You should have received a copy of the GNU General Public License
;;; along with guile-gcrypt.  If not, see <http://www.gnu.org/licenses/>.

(define-module (gcrypt internal)
  #:export (define-enumerate-type
            define-lookup-procedure))

;;; Code:
;;;
;;; This module provides tools for internal use.  The API of this module may
;;; change anytime; you should not rely on it.
;;;
;;; Comment:

(define-syntax-rule (define-enumerate-type name->integer symbol->integer
                      (name id) ...)
  (begin
    (define-syntax name->integer
      (syntax-rules (name ...)
        "Return hash algorithm NAME."
        ((_ name) id) ...))

    (define symbol->integer
      (let ((alist '((name . id) ...)))
        (lambda (symbol)
          "Look up SYMBOL and return the corresponding integer or #f if it
could not be found."
          (assq-ref alist symbol))))))

(define-syntax define-lookup-procedure
  (lambda (s)
    "Define LOOKUP as a procedure that maps an integer to its corresponding
value in O(1)."
    (syntax-case s ()
      ((_ lookup docstring (index value) ...)
       (let* ((values (syntax->datum #'((index . value) ...)))
              (min    (apply min (syntax->datum #'(index ...))))
              (max    (apply max (syntax->datum #'(index ...))))
              (array  (let loop ((i max)
                                 (result '()))
                        (if (< i (- min 1))
                            result
                            (loop (- i 1)
                                  (cons (or (assv-ref values i) -1)
                                        result))))))
         #`(define lookup
             ;; Allocate a big sparse vector.
             (let ((values '#(#,@array)))
               (lambda (integer)
                 docstring
                 (and (<= integer #,max) (> integer #,min)
                      (let ((result (vector-ref values integer)))
                        (and (> result 0) result)))))))))))
