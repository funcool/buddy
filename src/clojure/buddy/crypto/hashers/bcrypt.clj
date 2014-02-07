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
  (:require [buddy.crypto.hashers.protocols :refer [IHasher]]
            [buddy.crypto.hashers.sha256 :refer [make-sha256]]
            [buddy.crypto.core :refer :all]
            [buddy.codecs :refer :all]
            [clojure.string :refer [split]])
  (:import (buddy.impl BCrypt)))

(defn make-bcrypt
  [password log-rouds]
  (let [salt    (BCrypt/gensalt log-rouds)
        passwd  (-> (make-sha256 password)
                    (BCrypt/hashpw salt))]
    (bytes->hex (str->bytes passwd))))

(defn make-password
  "Encrypts a raw string password using
  pbkdf2_sha1 algorithm and return formatted
  string."
  [pw]
  (format "bcrypt+sha256$%s" (make-bcrypt pw 11)))

(defn check-password
  "Check if a unencrypted password matches
  with another encrypted password."
  [attempt encrypted]
  (let [[t p] (split encrypted #"\$")]
    (if (not= t "bcrypt+sha256")
      (throw (IllegalArgumentException. "invalid type of hasher"))
      (BCrypt/hashpw attempt (bytes->str (hex->bytes p))))))

(defrecord Bcrypt []
  IHasher
  (verify [_ attempt encrypted]
    (check-password attempt encrypted))
  (make-hash [_ password salt]
    (make-password password))
  (make-hash [_ password]
    (make-password password)))
