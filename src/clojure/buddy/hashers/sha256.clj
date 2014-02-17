;; Copyright 2013 Andrey Antukh <niwi@niwi.be>
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

(ns buddy.hashers.sha256
  (:require [buddy.core.codecs :refer :all]
            [buddy.core.util :refer :all]
            [buddy.core.hash :refer [sha256]]
            [clojure.string :refer [split]])
  (:import (java.security MessageDigest)))

(defn make-sha256
  [password salt]
  (sha256 (->byte-array password)
          (->byte-array salt)))

(defn make-password
  "Encrypts a raw string password using
  sha256 hash algorithm and return formatted
  string."
  [pw & [{:keys [salt]}]]
  (let [bsalt         (if (nil? salt) (random-bytes 12) salt)
        password      (make-sha256 pw bsalt)]
    (format "sha256$%s$%s" (bytes->hex bsalt) password)))

(defn check-password
  "Check if a unencrypted password matches
  with another encrypted password."
  [attempt encrypted]
  (let [[t s p] (split encrypted #"\$")]
    (if (not= t "sha256")
      (throw (IllegalArgumentException. "invalid type of hasher"))
      (let [salt        (hex->bytes s)]
        (= (make-sha256 attempt salt) p)))))
