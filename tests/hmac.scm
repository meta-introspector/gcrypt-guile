;;; guile-gcrypt --- crypto tooling for guile
;;; Copyright © 2016 Christopher Allan Webber <cwebber@dustycloud.org>
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

(define-module (test-hmac)
  #:use-module (rnrs bytevectors)
  #:use-module (srfi srfi-64)
  #:use-module (gcrypt hmac))

(test-begin "hmac")

(test-equal "lookup-mac-algorithm"
  (mac-algorithm sha3-256)
  (lookup-mac-algorithm 'sha3-256))

(test-equal "mac-size"
  (list 32 28 64 64)
  (map mac-size
       (list (mac-algorithm sha256)
             (mac-algorithm sha224)
             (mac-algorithm sha512)
             (mac-algorithm sha3-512))))

(define test-key (gen-signing-key))

(let ((sig (sign-data test-key "monkey party"
                      #:algorithm 'sha256)))    ;calling convention for 0.1.0
  ;; Should be a bytevector
  (test-assert (bytevector? sig))
  ;; Correct sig succeeds
  (test-assert (verify-sig test-key "monkey party" sig
                           #:algorithm 'sha256))
  ;; Incorrect data fails
  (test-assert (not (verify-sig test-key "something else" sig
                                #:algorithm (mac-algorithm sha256))))
  ;; Fake signature fails
  (test-assert (not (verify-sig test-key "monkey party"
                                (string->utf8 "fake sig")
                                #:algorithm (mac-algorithm sha256))))
  ;; Wrong algorithm fails
  (test-assert (not (verify-sig test-key "monkey party" sig
                                #:algorithm (mac-algorithm sha512))))
  ;; Should equal a re-run of itself
  (test-equal sig (sign-data test-key "monkey party"
                             #:algorithm (mac-algorithm sha256)))
  ;; Shouldn't equal something different
  (test-assert (not (equal? sig (sign-data test-key "cookie party"
                                           #:algorithm (mac-algorithm sha256))))))

;; Now with base64 encoding
(let ((sig (sign-data-base64 test-key "monkey party")))
  ;; Should be a string
  (test-assert (string? sig))
  ;; Correct sig succeeds
  (test-assert (verify-sig-base64 test-key "monkey party" sig))
  ;; Incorrect data fails
  (test-assert (not (verify-sig-base64 test-key "something else" sig)))
  ;; Fake signature fails
  (test-assert (not (verify-sig-base64 test-key "monkey party"
                                       "f41c3516")))
  ;; Should equal a re-run of itself
  (test-equal sig (sign-data-base64 test-key "monkey party"))
  ;; Shouldn't equal something different
  (test-assert (not (equal? sig (sign-data-base64 test-key "cookie party")))))

(test-end "hmac")
