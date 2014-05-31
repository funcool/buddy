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

(ns buddy.core.mac.shmac
  "Salted variant of Hash-based Message Authentication Codes (HMACs)"
  (:import clojure.lang.Keyword)
  (:require [buddy.core.codecs :refer :all]
            [buddy.core.mac.hmac :as hmac]
            [buddy.core.hash :as hash]))

(defn- make-salted-hmac
  [input key salt ^Keyword alg]
  (let [key (concat-byte-arrays (->byte-array key)
                                (->byte-array salt))]
    (hmac/hmac input (hash/sha512 key) alg)))

(defn- verify-salted-hmac
  [input ^bytes signature key salt ^Keyword alg]
  (let [key (concat-byte-arrays (->byte-array key)
                                (->byte-array salt))]
    (hmac/verify input signature (hash/sha512 key) alg)))

(defn shmac
  "Generic function that exposes a high level
interface for salted variant of keyed-hash message
authentication code algorithm."
  [input key salt ^Keyword alg]
  (make-salted-hmac input key salt alg))

(defn verify
  "Generic function that exposes a high level
interface for salted variant of keyed-hash message
authentication code verification algorithm."
  [input ^bytes signature key salt ^Keyword alg]
  (verify-salted-hmac input signature key salt alg))

