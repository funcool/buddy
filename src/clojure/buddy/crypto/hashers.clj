(ns buddy.crypto.hashers
  (:require [buddy.crypto.hashers.protocols :as proto]
            [buddy.crypto.hashers.pbkdf2 :as pbkdf2]
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
