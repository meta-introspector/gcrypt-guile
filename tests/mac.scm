;;; guile-gcrypt --- crypto tooling for guile
;;; Copyright © 2016 Christopher Allan Webber <cwebber@dustycloud.org>
;;; Copyright © 2019, 2020 Ludovic Courtès <ludo@gnu.org>
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
  #:use-module (gcrypt mac))

(test-begin "mac")

(test-equal "lookup-mac-algorithm"
  (mac-algorithm hmac-sha3-256)
  (lookup-mac-algorithm 'hmac-sha3-256))

(test-eq "mac-algorithm-name"
  'hmac-sha3-512
  (mac-algorithm-name (mac-algorithm hmac-sha3-512)))

(test-equal "mac-size"
  (list 32 28 64 64)
  (map mac-size
       (list (mac-algorithm hmac-sha256)
             (mac-algorithm hmac-sha224)
             (mac-algorithm hmac-sha512)
             (mac-algorithm hmac-sha3-512))))

(define test-key (generate-signing-key))

(let ((sig (sign-data test-key "monkey party"
                      #:algorithm (mac-algorithm hmac-sha256))))
  ;; Should be a bytevector
  (test-assert (bytevector? sig))
  ;; Correct sig succeeds
  (test-assert (valid-signature? test-key "monkey party" sig
                                 #:algorithm (mac-algorithm hmac-sha256)))
  ;; Incorrect data fails
  (test-assert (not (valid-signature? test-key "something else" sig
                                      #:algorithm
                                      (mac-algorithm hmac-sha256))))
  ;; Fake signature fails
  (test-assert (not (valid-signature? test-key "monkey party"
                                      (string->utf8 "fake sig")
                                      #:algorithm
                                      (mac-algorithm hmac-sha256))))
  ;; Wrong algorithm fails
  (test-assert (not (valid-signature? test-key "monkey party" sig
                                      #:algorithm
                                      (mac-algorithm hmac-sha512))))
  ;; Should equal a re-run of itself
  (test-equal sig (sign-data test-key "monkey party"
                             #:algorithm (mac-algorithm hmac-sha256)))
  ;; Shouldn't equal something different
  (test-assert (not (equal? sig (sign-data test-key "cookie party"
                                           #:algorithm
                                           (mac-algorithm hmac-sha256))))))

;; Now with a CMAC.
(let* ((key (generate-signing-key 16))
       (sig (sign-data key "monkey party"
                       #:algorithm (mac-algorithm cmac-aes))))
  ;; Should be a bytevector
  (test-assert (bytevector? sig))
  ;; Correct sig succeeds
  (test-assert (valid-signature? key "monkey party" sig
                                 #:algorithm (mac-algorithm cmac-aes)))
  ;; Fake signature fails
  (test-assert (not (valid-signature? key "monkey party"
                                      (string->utf8 "fake sig")
                                      #:algorithm (mac-algorithm cmac-aes)))))

;; Now with base64 encoding
(let ((sig (sign-data-base64 test-key "monkey party")))
  ;; Should be a string
  (test-assert (string? sig))
  ;; Correct sig succeeds
  (test-assert (valid-base64-signature? test-key "monkey party" sig))
  ;; Incorrect data fails
  (test-assert (not (valid-base64-signature? test-key "something else" sig)))
  ;; Fake signature fails
  (test-assert (not (valid-base64-signature? test-key "monkey party"
                                             "f41c3516")))
  ;; Should equal a re-run of itself
  (test-equal sig (sign-data-base64 test-key "monkey party"))
  ;; Shouldn't equal something different
  (test-assert (not (equal? sig (sign-data-base64 test-key "cookie party")))))

(test-end "mac")
