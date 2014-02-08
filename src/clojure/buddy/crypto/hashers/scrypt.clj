(ns buddy.crypto.hashers.scrypt
  (:require [buddy.codecs :refer :all]
            [buddy.crypto.core :refer :all]
            [clojure.string :refer [split]]
            [clojurewerkz.scrypt.core :as sc]))

(defn make-scrypt
  [password cpucost memcost parallelism]
  {:pre [(string? password)]}
  (sc/encrypt password cpucost memcost parallelism))

(defn make-password
  "Encrypts a raw string password using scrypt algorithm
and return formated string."
  [pw & [{:keys [salt cpucost memcost parallelism]
          :or {cpucost 65536 memcost 8 parallelism 1}}]]
  (let [salt   (cond 
                (nil? salt) (bytes->hex (random-bytes 12))
                (string? salt) salt
                (bytes? salt) (bytes->hex salt)
                :else (throw (IllegalArgumentException. "invalid salt type")))
        passwd (-> (str salt pw salt)
                   (make-scrypt cpucost memcost parallelism)
                   (str->bytes)
                   (bytes->hex))]
    (format "scrypt$%s$%s" salt passwd)))

(defn check-password
  "Check if a plaintext password matches with other
hashed password."
  [attempt hashed]
  (let [[t s pw] (split hashed #"\$")]
    (if (not= t "scrypt")
      (throw (IllegalArgumentException. "invalid type of hasher"))
      (let [hashed  (-> (hex->bytes pw)
                        (bytes->str))
            attempt (str s attempt s)]
        (sc/verify attempt hashed)))))
