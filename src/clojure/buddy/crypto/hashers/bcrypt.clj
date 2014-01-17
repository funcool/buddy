(ns buddy.crypto.hashers.bcrypt
  (:require [buddy.crypto.hashers.protocols :refer [IHasher]]
            [buddy.crypto.hashers.sha256 :refer [make-sha256]]
            [buddy.crypto.core :refer :all]
            [clojure.string :refer [split]])
  (:import (buddy.impl BCrypt)
           (javax.crypto.spec PBEKeySpec)
           (javax.crypto SecretKeyFactory)))

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
