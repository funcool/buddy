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

(ns buddy.hashers.scrypt
  (:require [buddy.core.codecs :refer :all]
            [buddy.core.keys :refer [make-random-bytes]]
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
                (nil? salt) (bytes->hex (make-random-bytes 12))
                :else (bytes->hex (->byte-array salt)))
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
