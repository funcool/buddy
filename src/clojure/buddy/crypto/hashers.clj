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

(ns buddy.crypto.hashers
  (:require [buddy.crypto.hashers.protocols :as proto]
            [buddy.crypto.hashers.pbkdf2 :as pbkdf2]
            [buddy.crypto.hashers.bcrypt :as bcrypt]
            [buddy.crypto.hashers.sha256 :as sha256]
            [buddy.crypto.hashers.md5 :as md5]))

(defn make-hasher
  "Given a keyword, return a new instance
  of hasher."
  ([] (make-hasher :pbkdf2-sha1))
  ([hashkw]
   (cond
     (= hashkw :pbkdf2-sha1) (pbkdf2/->Pbkdf2 20000)
     (= hashkw :pbkdf2) (make-hasher :pbkdf2-sha1)
     (= hashkw :bcrypt) (bcrypt/->Bcrypt)
     (= hashkw :sha256) (sha256/->Sha256)
     (= hashkw :md5) (md5/->Md5))))

(defn verify
  "Public interface of IHasher protocol."
  [hasher attempt encrypted]
  (proto/verify hasher attempt encrypted))

(defn make-hash
  "Public interface of IHasher protocol."
  ([hasher password salt]
   (proto/make-hash hasher password salt))
  ([hasher password]
   (proto/make-hash hasher password)))
