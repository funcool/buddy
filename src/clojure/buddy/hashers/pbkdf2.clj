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

(ns buddy.hashers.pbkdf2
  (:require [buddy.codecs :refer :all]
            [buddy.crypto.core :refer :all]
            [clojure.string :refer [split]]))

(defn make-pbkdf2
  [password salt iterations]
  {:pre [(string? password)]}
  (let [bpasswd (str->bytes password)
        bsalt   (cond
                 (string? salt) (str->bytes salt)
                 (bytes? salt) salt
                 :else (throw (IllegalArgumentException. "invalid salt type")))]
    (-> (buddy.impl.pbkdf2.Pbkdf2/deriveKey "HmacSHA256" bpasswd bsalt iterations 32)
        (bytes->hex))))

(defn make-password
  "Encrypts a raw string password using
  pbkdf2_sha1 algorithm and return formatted
  string."
  [pw & [{:keys [salt iterations] :or {iterations 20000}}]]
  (let [salt      (if (nil? salt) (random-bytes 12) salt)
        password  (make-pbkdf2 pw salt iterations)]
    (format "pbkdf2+sha1$%s$%s$%s" (bytes->hex salt) iterations password)))

(defn check-password
  "Check if a unencrypted password matches
  with another encrypted password."
  [attempt encrypted]
  (let [[t s i p] (split encrypted #"\$")]
    (if (not= t "pbkdf2+sha1")
      (throw (IllegalArgumentException. "invalid type of hasher"))
      (let [salt        (hex->bytes s)
            iterations  (Integer/parseInt i)]
        (= (make-pbkdf2 attempt salt iterations) p)))))
