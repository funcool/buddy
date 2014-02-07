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

(ns buddy.crypto.hashers.md5
  (:require [buddy.crypto.hashers.protocols :refer [IHasher]]
            [buddy.crypto.core :refer :all]
            [buddy.codecs :refer :all]
            [clojure.string :refer [split]])
  (:import (java.security MessageDigest)))

(defn make-md5
  [password salt]
  (let [passwd  (str->bytes password)
        salt    (cond
                  (string? salt) (str->bytes salt)
                  (bytes? salt) salt
                  :else (throw (IllegalArgumentException. "invalid salt type")))
        md      (doto (MessageDigest/getInstance "MD5")
                  (.update salt)
                  (.update passwd))]
    (bytes->hex (.digest md))))

(defn make-password
  "Encrypts a raw string password using
  md5 hash algorithm and return formatted
  string."
  [pw & [{:keys [salt]}]]
  (let [salt      (if (nil? salt) (random-bytes 12) salt)
        password  (make-md5 pw salt)]
    (format "md5$%s$%s" (bytes->hex salt) password)))

(defn check-password
  "Check if a unencrypted password matches
  with another encrypted password."
  [attempt encrypted]
  (let [[t s p] (split encrypted #"\$")]
    (if (not= t "md5")
      (throw (IllegalArgumentException. "invalid type of hasher"))
      (let [salt        (hex->bytes s)]
        (= (make-md5 attempt salt) p)))))

(defrecord Md5 []
  IHasher
  (verify [_ attempt encrypted]
    (check-password attempt encrypted))
  (make-hash [_ password salt]
    (make-password password {:salt salt}))
  (make-hash [_ password]
    (make-password password)))
