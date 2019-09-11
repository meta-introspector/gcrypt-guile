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

(define-module (gcrypt hmac)
  #:use-module ((gcrypt mac) #:prefix mac:)
  #:export (sign-data
            sign-data-base64
            verify-sig
            verify-sig-base64
            gen-signing-key))

;;; Code:
;;;
;;; This module is deprecated and provided for compatibility with
;;; Guile-Gcrypt 0.1.0.  Use (gcrypt mac) instead.
;;;
;;; Commentary:

(define* (sign-data key data #:key (algorithm 'sha512))
  "Signs DATA with KEY for ALGORITHM.  Returns a bytevector."
  (mac:sign-data key data
                 #:algorithm
                 (mac:lookup-mac-algorithm algorithm)))

(define* (sign-data-base64 key data #:key (algorithm 'sha512))
  "Signs DATA with KEY for ALGORITHM.  Returns a bytevector."
  (mac:sign-data-base64 key data
                        #:algorithm
                        (mac:lookup-mac-algorithm algorithm)))

(define* (verify-sig key data sig #:key (algorithm 'sha512))
  "Verify that DATA with KEY matches previous signature SIG for ALGORITHM."
  (mac:verify-sig key data sig
                  #:algorithm
                  (mac:lookup-mac-algorithm algorithm)))

(define* (verify-sig-base64 key data sig #:key (algorithm 'sha512))
  "Verify that DATA with KEY matches previous signature SIG for ALGORITHM."
  (mac:verify-sig-base64 key data sig
                         #:algorithm
                         (mac:lookup-mac-algorithm algorithm)))

(define gen-signing-key
  mac:gen-signing-key)
