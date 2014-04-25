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
  (:require buddy.core.mac.hmac))

(defmacro pullall [ns]
  `(do ~@(for [i (map first (ns-publics ns))]
           `(def ~i ~(symbol (str ns "/" i))))))

(pullall buddy.core.mac.hmac)
