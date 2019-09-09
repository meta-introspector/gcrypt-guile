;;; guile-gcrypt --- crypto tooling for guile
;;; Copyright © 2016 Christopher Allan Webber <cwebber@dustycloud.org>
;;; Copyright © 2019 Mathieu Othacehe <m.othacehe@gmail.com>
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
  #:use-module (ice-9 format)
  #:use-module (ice-9 match)
  #:use-module (gcrypt base64)
  #:use-module (gcrypt common)
  #:use-module (gcrypt internal)
  #:use-module (gcrypt random)
  #:use-module (rnrs bytevectors)
  #:use-module (system foreign)
  #:export (mac-algorithm
            lookup-mac-algorithm
            mac-size

            sign-data
            sign-data-base64
            verify-sig verify-sig-base64
            gen-signing-key))

;;; HMAC
;;; ====

(define-syntax-rule (define-mac-algorithms name->integer
                      symbol->integer mac-size
                      (name id size) ...)
  "Define hash algorithms with their NAME, numerical ID, and SIZE in bytes."
  (begin
    (define-enumerate-type name->integer symbol->integer
      (name id) ...)

    (define-lookup-procedure mac-size
      "Return the size in bytes of a digest of the given hash algorithm."
      (id size) ...)))

(define-mac-algorithms mac-algorithm
  lookup-mac-algorithm
  mac-size

  (sha256 101 32)
  (sha512 103 64)
  (sha3-256 116 32)
  (sha3-512 118 64))

(define mac-algo-maclen
  ;; This procedure was used to double-check the hash sizes above.  (We
  ;; cannot use it at macro-expansion time because it wouldn't work when
  ;; cross-compiling.)
  (libgcrypt->procedure int "gcry_mac_get_algo_maclen" `(,int)))

(define-inlinable (ensure-mac-algorithm obj)
  ;; In Guile-Gcrypt 0.1.0, public procedures would accept a symbol to
  ;; describe the algorithm.  This procedure is here to support this
  ;; backward-compatibility.
  (if (symbol? obj)
      (lookup-mac-algorithm obj)
      obj))

(define %no-error 0)  ; GPG_ERR_NO_ERROR

(define-wrapped-pointer-type <mac>
  mac?
  pointer->mac mac->pointer
  (lambda (mac port)
    (format port "#<mac ~x>"
            (pointer-address (mac->pointer mac)))))

(define %gcry-mac-open
  (libgcrypt->procedure int "gcry_mac_open"
                        ;; gcry_mac_hd_t *HD, int ALGO,
                        ;; unsigned int FLAGS, gcry_ctx_t CTX
                        `(* ,int ,unsigned-int *)))

(define (mac-open algorithm)
  "Create a <mac> object set to use ALGORITHM"
  (let* ((mac (bytevector->pointer (make-bytevector (sizeof '*))))
         (err (%gcry-mac-open mac algorithm 0 %null-pointer)))
    (if (= err 0)
        (pointer->mac (dereference-pointer mac))
        (throw 'gcry-error 'mac-open err))))

(define %gcry-mac-setkey
  (libgcrypt->procedure int "gcry_mac_setkey" `(* * ,size_t)))

(define (mac-setkey mac key)
  "Set the KEY on <mac> object MAC

In our case, KEY is either a string or a bytevector."
  (let* ((key (match key
                ((? bytevector? key)
                 key)
                ((? string? key)
                 (string->utf8 key))))
         (err (%gcry-mac-setkey (mac->pointer mac)
                                (bytevector->pointer key)
                                (bytevector-length key))))
    (if (= err 0)
        #t
        (throw 'gcry-error 'mac-setkey err))))

(define mac-close
  (let ((proc (libgcrypt->procedure void
                                    "gcry_mac_close"
                                    '(*))))  ; gcry_mac_hd_t H
    (lambda (mac)
      "Release all resources of MAC.

Running this on an already closed <mac> might segfault :)"
      (proc (mac->pointer mac)))))

(define mac-write
  (let ((proc (libgcrypt->procedure int
                                    "gcry_mac_write"
                                    `(* * ,size_t))))
    (lambda (mac obj)
      "Writes string or bytevector OBJ to MAC"
      (let* ((bv (match obj
                   ((? bytevector? obj)
                    obj)
                   ((? string? obj)
                    (string->utf8 obj))))
             (err (proc (mac->pointer mac)
                        (bytevector->pointer bv)
                        (bytevector-length bv))))
        (if (= err 0)
            #t
            (throw 'gcry-error 'mac-write err))))))

(define mac-read
  (let ((proc (libgcrypt->procedure int
                                    "gcry_mac_read"
                                    `(* * *))))
    (lambda (mac algorithm)
      "Get bytevector representing result of MAC's written, signed data"
      (define (int-bv* n)
        ;; Get the pointer to a bytevector holding an integer with this number
        (let ((bv (make-bytevector (sizeof int))))
          (bytevector-uint-set! bv 0 n (native-endianness) (sizeof int))
          (bytevector->pointer bv)))
      (let* ((bv-len (mac-size algorithm))
             (bv (make-bytevector bv-len))
             (err (proc (mac->pointer mac)
                        (bytevector->pointer bv)
                        (int-bv* bv-len))))
        (if (= err 0)
            bv
            (throw 'gcry-error 'mac-read err))))))

;; GPG_ERR_CHECKSUM *should* be 10, but it seems to return here as
;; 16777226... unfortunately this is because we're pulling back an integer
;; rather than the gcry_error_t type.

(define mac-verify
  (let ((proc (libgcrypt->procedure int
                                    "gcry_mac_verify"
                                    `(* * ,size_t))))
    (lambda (mac bv)
      "Verify that BV matches result calculated in MAC

BV should be a bytevector with previously calculated data."
      (let ((err (proc (mac->pointer mac)
                       (bytevector->pointer bv)
                       (bytevector-length bv))))
        (if (= err 0)
            (values #t err)
            ;; TODO: This is WRONG!  See the comment above
            ;;   this procedure's definition for why.  If we could
            ;;   parse it as the appropriate GPG error, GPG_ERR_CHECKSUM
            ;;   should be 10.
            (values #f err))))))

(define* (sign-data key data #:key
                    (algorithm (mac-algorithm sha512)))
  "Signs DATA with KEY for ALGORITHM.  Returns a bytevector."
  (let* ((algorithm (ensure-mac-algorithm algorithm))
         (mac (mac-open algorithm)))
    (mac-setkey mac key)
    (mac-write mac data)
    (let ((result (mac-read mac algorithm)))
      (mac-close mac)
      result)))

(define* (sign-data-base64 key data #:key
                           (algorithm (mac-algorithm sha512)))
  "Like sign-data, but conveniently encodes to base64."
  (let ((algorithm (ensure-mac-algorithm algorithm)))
    (base64-encode (sign-data key data #:algorithm algorithm))))


;; @@: Shouldn't this be "valid-sig?"
(define* (verify-sig key data sig
                     #:key (algorithm (mac-algorithm sha512)))
  "Verify that DATA with KEY matches previous signature SIG for ALGORITHM."
  (let* ((algorithm (ensure-mac-algorithm algorithm))
         (mac (mac-open algorithm)))
    (mac-setkey mac key)
    (mac-write mac data)
    (let ((result (mac-verify mac sig)))
      (mac-close mac)
      result)))

(define* (verify-sig-base64 key data b64-sig
                            #:key (algorithm (mac-algorithm sha512)))
  (verify-sig key data
               (base64-decode b64-sig)
               #:algorithm algorithm))

(define* (gen-signing-key #:optional (key-length 128))
  "Generate a signing key (a bytevector).

KEY-LENGTH is the length, in bytes, of the key.  The default is 128.
This should be a multiple of 8."
  (gen-random-bv key-length %gcry-very-strong-random))
