;;; guile-gcrypt --- crypto tooling for guile
;;;
;;; Code taken from:
;;;
;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014 Nikita Karetnikov <nikita@karetnikov.org>
;;;
;;; This file is part of guile-gcrypt.
;;;
;;; guile-gcrypt is free software; you can redistribute it and/or
;;; modify it under the terms of the GNU Lesser General Public License
;;; as published by the Free Software Foundation; either version 3 of
;;; the License, or (at your option) any later version.
;;;
;;; guile-gcrypt is distributed in the hope that it will be useful, but
;;; WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
;;; Lesser General Public License for more details.
;;;
;;; You should have received a copy of the GNU Lesser General Public License
;;; along with guile-gcrypt.  If not, see <http://www.gnu.org/licenses/>.


(define-module (test-base64)
  #:use-module (gcrypt base64)
  #:use-module (rnrs bytevectors)
  #:use-module (srfi srfi-64))

(define (string->base64 str)
  (base64-encode (string->utf8 str)))

(define (base64->string base64)
  (utf8->string (base64-decode base64)))

(define (string->base64-padding str padding)
  (let ((bv (string->utf8 str)))
    (base64-encode bv 0 (bytevector-length bv) #f (not padding))))

(define (base64->string-padding base64 padding)
  (utf8->string (base64-decode base64 base64url-alphabet #f #f padding)))

;;; Test vectors from <https://tools.ietf.org/rfc/rfc4648.txt>.

(test-begin "base64")

;; Encoding

(test-equal "empty string"
  (string->base64 "")
  "")

(test-equal "f"
  (string->base64 "f")
  "Zg==")

(test-equal "fo"
  (string->base64 "fo")
  "Zm8=")

(test-equal "foo"
  (string->base64 "foo")
  "Zm9v")

(test-equal "foob"
  (string->base64 "foob")
  "Zm9vYg==")

(test-equal "fooba"
  (string->base64 "fooba")
  "Zm9vYmE=")

(test-equal "foobar"
  (string->base64 "foobar")
  "Zm9vYmFy")

(test-equal "foob (no padding)"
  (string->base64-padding "foob" #f)
  "Zm9vYg")

(test-equal "foob (padding)"
  (string->base64-padding "foob" #t)
  "Zm9vYg==")

;; Decoding

(test-equal "empty string"
  (base64->string "")
  "")

(test-equal "f"
  (base64->string "Zg==")
  "f")

(test-equal "fo"
  (base64->string "Zm8=")
  "fo")

(test-equal "foo"
  (base64->string "Zm9v")
  "foo")

(test-equal "foob"
  (base64->string "Zm9vYg==")
  "foob")

(test-equal "fooba"
  (base64->string "Zm9vYmE=")
  "fooba")

(test-equal "foobar"
  (base64->string "Zm9vYmFy")
  "foobar")

(test-equal "foob (no padding)"
  (base64->string-padding "Zm9vYg" #f)
  "foob")

(test-equal "foob (padding)"
  (base64->string-padding "Zm9vYg==" #t)
  "foob")

(test-end "base64")
