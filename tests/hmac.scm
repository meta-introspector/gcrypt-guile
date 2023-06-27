;;; guile-gcrypt --- crypto tooling for guile
;;; Copyright © 2016 Christine Lemmer-Webber <cwebber@dustycloud.org>
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

(define-module (test-mac)
  #:use-module (rnrs bytevectors)
  #:use-module (srfi srfi-64)
  #:use-module (gcrypt hmac))                     ;the deprecated module

(test-begin "hmac")

(define test-key (gen-signing-key))

(let ((sig (sign-data test-key "monkey party"
                      #:algorithm 'sha256)))
  ;; Should be a bytevector
  (test-assert (bytevector? sig))

  ;; Correct sig succeeds
  (test-assert (verify-sig test-key "monkey party" sig
                           #:algorithm 'sha256)))

(let ((sig (sign-data test-key "monkey party")))
  ;; Should be a bytevector
  (test-assert (bytevector? sig))

  ;; Correct sig succeeds
  (test-assert (verify-sig test-key "monkey party" sig)))

(test-end "hmac")
