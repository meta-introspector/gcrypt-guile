;;; guile-gcrypt --- crypto tooling for guile
;;; Copyright © 2013, 2014, 2015 Ludovic Courtès <ludo@gnu.org>
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

(define-module (gcrypt common)
  #:use-module (gcrypt package-config)
  #:use-module (system foreign)
  #:use-module (ice-9 match)
  #:export (gcrypt-version
            libgcrypt-func
            error-source error-string))

;;; Commentary:
;;;
;;; Common code for the GNU Libgcrypt bindings.  Loading this module
;;; initializes Libgcrypt as a side effect.
;;;
;;; Code:

(define libgcrypt-func
  (let ((lib (dynamic-link %libgcrypt)))
    (lambda (func)
      "Return a pointer to symbol FUNC in libgcrypt."
      (dynamic-func func lib))))

(define gcrypt-version
  ;; According to the manual, this function must be called before any other,
  ;; and it's not clear whether it can be called more than once.  So call it
  ;; right here from the top level.
  (let* ((ptr     (libgcrypt-func "gcry_check_version"))
         (proc    (pointer->procedure '* ptr '(*)))
         (version (pointer->string (proc %null-pointer))))
    (lambda ()
      "Return the version number of libgcrypt as a string."
      version)))

(define error-source
  (let* ((ptr  (libgcrypt-func "gcry_strsource"))
         (proc (pointer->procedure '* ptr (list int))))
    (lambda (err)
      "Return the error source (a string) for ERR, an error code as thrown
along with 'gcry-error'."
      (pointer->string (proc err)))))

(define error-string
  (let* ((ptr  (libgcrypt-func "gcry_strerror"))
         (proc (pointer->procedure '* ptr (list int))))
    (lambda (err)
      "Return the error description (a string) for ERR, an error code as
thrown along with 'gcry-error'."
      (pointer->string (proc err)))))

(define (gcrypt-error-printer port key args default-printer)
  "Print the gcrypt error specified by ARGS."
  (match args
    ((proc err)
     (format port "In procedure ~a: ~a: ~a"
             proc (error-source err) (error-string err)))))

(set-exception-printer! 'gcry-error gcrypt-error-printer)

;;; gcrypt.scm ends here
