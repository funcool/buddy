(ns buddy.crypto.hashers
  (:require [buddy.crypto.hashers.protocols :as proto]
            [buddy.crypto.hashers.pbkdf2 :as pbkdf2]))

(defn hasher
  "Given a keyword, return a new instance
  of hasher."
  [hashkw]
  (cond
    (= hashkw :pbkdf2-sha1) (pbkdf2/->Pbkdf2 20000)))

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
