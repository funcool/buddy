;; Copyright 2014 Andrey Antukh <niwi@niwi.be>
;;
;; Licensed under the Apache License, Version 2.0 (the "License")
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at
;;
;;     http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.

(ns buddy.core.hmac
  "Hash-based Message Authentication Codes (HMACs)
This namespace is now deprecated in favour of buddy.core.mac.hmac
and mantained for backward comaptibility."
  (:import clojure.lang.Keyword)
  (:require buddy.core.mac.hmac
            buddy.core.mac.shmac))

(defmacro pullall [ns]
  `(do ~@(for [i (map first (ns-publics ns))]
           `(def ~i ~(symbol (str ns "/" i))))))

(pullall buddy.core.mac.hmac)
(pullall buddy.core.mac.shmac)

(def hmac-verify buddy.core.mac.hmac/verify)
(def shmac-verify buddy.core.mac.shmac/verify)


;; Alias for hmac + sha2 hash algorithms
(def hmac-sha256 #(buddy.core.mac.hmac/hmac %1 %2 :sha256))
(def hmac-sha384 #(buddy.core.mac.hmac/hmac %1 %2 :sha384))
(def hmac-sha512 #(buddy.core.mac.hmac/hmac %1 %2 :sha512))
(def hmac-sha256-verify #(buddy.core.mac.hmac/verify %1 %2 %3 :sha256))
(def hmac-sha384-verify #(buddy.core.mac.hmac/verify %1 %2 %3 :sha384))
(def hmac-sha512-verify #(buddy.core.mac.hmac/verify %1 %2 %3 :sha512))

;; Alias for salted hmac + sha2 hash algorithms
(def shmac-sha256 #(buddy.core.mac.shmac/shmac %1 %2 %3 :sha256))
(def shmac-sha384 #(buddy.core.mac.shmac/shmac %1 %2 %3 :sha384))
(def shmac-sha512 #(buddy.core.mac.shmac/shmac %1 %2 %3 :sha512))
(def shmac-sha256-verify #(buddy.core.mac.shmac/verify %1 %2 %3 %4 :sha256))
(def shmac-sha384-verify #(buddy.core.mac.shmac/verify %1 %2 %3 %4 :sha384))
(def shmac-sha512-verify #(buddy.core.mac.shmac/verify %1 %2 %3 %4 :sha512))
