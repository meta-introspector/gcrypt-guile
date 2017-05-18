;;; guile-gcrypt --- crypto tooling for guile
;;; Copyright © 2016 Christopher Allan Webber <cwebber@dustycloud.org>
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

(use-modules (guix packages)
             (guix build-system gnu)
             (guix download)
             (guix git-download)
             (guix gexp)
             ((guix build utils) #:select (with-directory-excursion))
             (gnu packages)
             (gnu packages autotools)
             (gnu packages base)
             (gnu packages guile)
             (gnu packages pkg-config)
             (gnu packages texinfo)
             (gnu packages gnupg)
             (guix licenses))

(define %source-dir (dirname (current-filename)))

(define guile-gcrypt
  (package
    (name "guile-gcrypt")
    (version "git")
    (source (local-file %source-dir
                        #:recursive? #t
                        #:select? (git-predicate %source-dir)))
    (build-system gnu-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'bootstrap
           (lambda _ (zero? (system* "sh" "bootstrap.sh")))))))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("autoconf" ,autoconf)
       ("automake" ,automake)
       ("texinfo" ,texinfo)))
    (inputs
     `(("guile" ,guile-2.2)
       ("libgcrypt" ,libgcrypt)))
    (home-page "https://notabug.org/cwebber/guile-gcrypt")
    (synopsis "")
    (description "ActivityStreams and ActivityPub implementation in Guile.
Includes a full (currently demo) web server.")
    (license gpl3+)))

guile-gcrypt
