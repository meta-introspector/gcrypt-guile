;;; guile-gcrypt --- crypto tooling for guile
;;; Copyright © 2013, 2014, 2017, 2019, 2020 Ludovic Courtès <ludo@gnu.org>
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

(define-module (test-hash)
  #:use-module (gcrypt hash)
  #:use-module (gcrypt base16)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-11)
  #:use-module (srfi srfi-64)
  #:use-module (rnrs bytevectors)
  #:use-module (rnrs io ports))

;; Test the (guix hash) module.

(define %empty-sha256
  ;; SHA256 hash of the empty string.
  (base16-string->bytevector
   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))

(define %hello-sha256
  ;; SHA256 hash of "hello world"
  (base16-string->bytevector
   "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"))

(define %hello-sha512
  (base16-string->bytevector
   "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"))

(define (supports-unbuffered-cbip?)
  "Return #t if unbuffered custom binary input ports (CBIPs) are supported.
In Guile <= 2.0.9, CBIPs were always fully buffered, so the
'open-hash-input-port' does not work there."
  (false-if-exception
   (setvbuf (make-custom-binary-input-port "foo" pk #f #f #f)
            (cond-expand ((and guile-2 (not guile-2.2)) _IONBF)
                         (else 'none)))))


(test-begin "hash")

(test-equal "lookup-hash-algorithm"
  (hash-algorithm blake2b-512)
  (lookup-hash-algorithm 'blake2b-512))

(test-eq "hash-algorithm-name"
  'sha3-512
  (hash-algorithm-name (hash-algorithm sha3-512)))

(test-equal "hash-size"
  (list 20 32 64)
  (map hash-size
       (list (hash-algorithm sha1)
             (hash-algorithm sha256)
             (hash-algorithm sha512))))

(test-equal "sha1, empty"
  (base16-string->bytevector "da39a3ee5e6b4b0d3255bfef95601890afd80709")
  (sha1 #vu8()))

(test-equal "sha1, hello"
  (base16-string->bytevector "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed")
  (sha1 (string->utf8 "hello world")))

(test-equal "sha256, empty"
  %empty-sha256
  (sha256 #vu8()))

(test-equal "sha256, hello"
  %hello-sha256
  (sha256 (string->utf8 "hello world")))

(test-equal "sha512, empty"
  "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
  (bytevector->base16-string (sha512 #vu8())))

(test-equal "sha512, hello"
  %hello-sha512
  (bytevector-hash (string->utf8 "hello world")
                   (hash-algorithm sha512)))

(test-equal "open-sha256-port, empty"
  %empty-sha256
  (let-values (((port get)
                (open-sha256-port)))
    (close-port port)
    (get)))

(test-equal "open-sha256-port, hello"
  (list %hello-sha256 (string-length "hello world"))
  (let-values (((port get)
                (open-sha256-port)))
    (put-bytevector port (string->utf8 "hello world"))
    (force-output port)
    (list (get) (port-position port))))

(test-equal "open-hash-port, sha512, hello"
  (list %hello-sha512 (string-length "hello world"))
  (let-values (((port get)
                (open-hash-port (hash-algorithm sha512))))
    (put-bytevector port (string->utf8 "hello world"))
    (force-output port)
    (list (get) (port-position port))))

(test-assert "port-sha256"
  (let* ((file     (search-path %load-path "ice-9/psyntax.scm"))
         (size     (stat:size (stat file)))
         (contents (call-with-input-file file get-bytevector-all)))
    (equal? (sha256 contents)
            (call-with-input-file file port-sha256))))

(test-skip (if (supports-unbuffered-cbip?) 0 4))

(test-equal "open-sha256-input-port, empty"
  `("" ,%empty-sha256)
  (let-values (((port get)
                (open-sha256-input-port (open-string-input-port ""))))
    (let ((str (get-string-all port)))
      (list str (get)))))

(test-equal "open-sha256-input-port, hello"
  `("hello world" ,%hello-sha256)
  (let-values (((port get)
                (open-sha256-input-port
                 (open-bytevector-input-port
                  (string->utf8 "hello world")))))
    (let ((str (get-string-all port)))
      (list str (get)))))

(test-equal "open-hash-input-port, sha512, hello"
  `("hello world" ,%hello-sha512)
  (let-values (((port get)
                (open-hash-input-port
                 (hash-algorithm sha512)
                 (open-bytevector-input-port
                  (string->utf8 "hello world")))))
    (let ((str (get-string-all port)))
      (list str (get)))))

(test-equal "open-sha256-input-port, hello, one two"
  (list (string->utf8 "hel") (string->utf8 "lo")
        (base16-string->bytevector                ; echo -n hello | sha256sum
         "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        " world")
  (let-values (((port get)
                (open-sha256-input-port
                 (open-bytevector-input-port (string->utf8 "hello world")))))
    (let* ((one   (get-bytevector-n port 3))
           (two   (get-bytevector-n port 2))
           (hash  (get))
           (three (get-string-all port)))
      (list one two hash three))))

(test-equal "open-sha256-input-port, hello, read from wrapped port"
  (list (string->utf8 "hello")
        (base16-string->bytevector                ; echo -n hello | sha256sum
         "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        " world")
  (let*-values (((wrapped)
                 (open-bytevector-input-port (string->utf8 "hello world")))
                ((port get)
                 (open-sha256-input-port wrapped)))
    (let* ((hello (get-bytevector-n port 5))
           (hash  (get))

           ;; Now read from WRAPPED to make sure its current position is
           ;; correct.
           (world (get-string-all wrapped)))
      (list hello hash world))))

(test-end)
