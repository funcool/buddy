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

(ns buddy.crypto.hashers.bcrypt
  (:require [buddy.crypto.hashers.sha256 :refer [make-sha256]]
            [buddy.crypto.core :refer :all]
            [buddy.codecs :refer :all]
            [clojure.string :refer [split]])
  (:import (buddy.impl BCrypt)))

(defn make-bcrypt
  [password log-rouds]
  (let [salt    (BCrypt/gensalt log-rouds)]
    (-> (make-sha256 password)
        (BCrypt/hashpw salt))))

(defn make-password
  "Encrypts a raw string password using
  pbkdf2_sha1 algorithm and return formatted
  string."
  [pw & [{:keys [salt rounds] :or {rounds 12}}]]
  (let [salt   (cond
                (nil? salt) (bytes->hex (random-bytes 12))
                (string? salt) salt
                (bytes? salt) (bytes->hex salt)
                :else (throw (IllegalArgumentException. "invalid salt type")))
        passwd (-> (str salt pw salt)
                   (make-bcrypt rounds)
                   (str->bytes)
                   (bytes->hex))]
    (format "bcrypt+sha256$%s$%s" salt passwd)))

(defn check-password
  "Check if a plaintext password matches with other
hashed password."
  [attempt hashed]
  (let [[t s p] (split hashed #"\$")]
    (if (not= t "bcrypt+sha256")
      (throw (IllegalArgumentException. "invalid type of hasher"))
      (let [hashed  (-> (hex->bytes p)
                        (bytes->str))
            attempt (-> (str s attempt s)
                        (make-sha256))]
        (BCrypt/checkpw attempt hashed)))))
