(ns buddy.crypto.hashers.md5
  (:require [buddy.crypto.hashers.protocols :refer [IHasher]]
            [buddy.crypto.core :refer :all]
            [clojure.string :refer [split]])
  (:import (java.security MessageDigest)))

(defn- make-md5
  [password salt]
  {:pre [(or (nil? salt) (bytes? salt))]}
  (let [ba-passwd (str->bytes password)
        md        (doto (MessageDigest/getInstance "MD5")
                    (.update salt)
                    (.update ba-passwd))]
    (bytes->hex (.digest md))))

(defn make-password
  "Encrypts a raw string password using
  md5 hash algorithm and return formatted
  string."
  [pw & [{:keys [salt]}]]
  {:pre [(or (nil? salt) (bytes? salt))]}
  (let [bsalt         (if (nil? salt) (random-bytes 12) salt)
        password      (make-md5 pw bsalt)]
    (format "md5$%s$%s" (bytes->hex bsalt) password)))

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
    (make-password password {:salt (str->bytes salt)}))
  (make-hash [_ password]
    (make-password password)))
